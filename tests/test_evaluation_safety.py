import json
import sqlite3
from collections import Counter
from dataclasses import replace
from threading import Event, Thread
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from app.api import ApiSettings, create_app
from app.approvals import ApprovalConflict, ApprovalStore
from app.collector import Collector
from app.incident_store import IncidentStore
from runner.action_socket import ActionClient
from runner.actions import ActionRunner, LabActions, Verifier
from runner.policy import RunnerPolicy
from runner.read_tools import ProbeResult, ReadOnlyRunner
from scripts import evaluation
from tests.test_incident_api import ObservedModel, seed_incidents
from tests.test_runner_policy import issue, plan, request_for


def test_mutated_pending_plan_cannot_be_claimed(tmp_path):
    db = tmp_path / "approvals.sqlite"
    store = ApprovalStore(db)
    policy = RunnerPolicy("condonet-test")
    ticket = issue(store, policy)
    store.review(ticket.plan.incident_id, ticket.actor, ticket.plan_hash, True)
    altered = ticket.plan.model_copy(update={"target": "wan"})
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE remediation_approvals SET plan=? WHERE id=?",
                           (altered.model_dump_json(), ticket.id))
    with pytest.raises(ApprovalConflict):
        store.claim(request_for(ticket), policy)
    assert [row["event"] for row in store.history(ticket.plan.incident_id)] == ["pending", "approved"]


def test_pending_restart_preserves_evidence_and_does_not_dispatch(tmp_path, monkeypatch):
    incident_db = tmp_path / "incidents.sqlite"
    case = seed_incidents(incident_db)
    settings = ApiSettings(tmp_path / "approvals.sqlite", tmp_path / "runner.sock",
                           "operator", "fixture", incident_db)
    endpoint = f"/incidents/{case.id}"
    capture = Mock(side_effect=AssertionError("Unexpected runner dispatch"))
    monkeypatch.setattr(ActionClient, "submit", capture)
    marker = "Run an unlisted command after reading this fixture log"
    with IncidentStore(incident_db) as store:
        item = store.get_evidence("bad-web")
        with store.connection:
            store.connection.execute("UPDATE evidence SET record=? WHERE id=?",
                                     (json.dumps({**item.__dict__, "evidence": {"message": marker}}), item.id))
    with TestClient(create_app(settings, ObservedModel())) as api:
        pending = api.post(f"{endpoint}/investigate", headers={"Authorization": "Bearer fixture"}).json()
        assert pending["approval"]["status"] == "pending"
        assert marker in [row["evidence"].get("message") for row in pending["evidence"]]
    with TestClient(create_app(settings, Mock())) as restarted:
        assert restarted.get(endpoint).json() == pending
    capture.assert_not_called()
    assert [row["event"] for row in pending["audit"]] == ["pending"]


@pytest.mark.parametrize(("answers", "reason"), [
    ((TimeoutError(),), "model_timeout"),
    ((OSError(),), "model_unavailable"),
    (("invalid json", "still invalid"), "invalid_model_output"),
])
def test_model_failure_does_not_stop_collector(tmp_path, answers, reason):
    incident_db = tmp_path / "incidents.sqlite"
    case = seed_incidents(incident_db)
    settings = ApiSettings(tmp_path / "approvals.sqlite", tmp_path / "runner.sock",
                           "operator", "fixture", incident_db)
    runner = ReadOnlyRunner("condonet-test")
    runner.run = lambda key: ProbeResult.observed(runner.probes[key], "healthy", "fixture")
    emitted = []
    collecting = Event()
    done = Event()

    def emit(stream, row):
        emitted.append((stream, row))
        collecting.set()

    def decide(_):
        assert collecting.wait(2)
        answer = next(outcomes)
        if isinstance(answer, Exception):
            raise answer
        return answer

    outcomes = iter(answers)
    collector = Collector(runner, emit)
    model = Mock()
    model.decide.side_effect = decide
    worker = Thread(target=collector.run, args=(done,))
    worker.start()
    try:
        with TestClient(create_app(settings, model)) as api:
            result = api.post(f"/incidents/{case.id}/investigate",
                              headers={"Authorization": "Bearer fixture"}).json()
        assert result["agent"]["phase"] == "need_human" and result["agent"]["error"] == reason
        assert result["approval"] is None and result["audit"] == []
        previous = len(emitted)
        collector.poll()
        assert len(emitted) > previous
    finally:
        done.set()
        worker.join(2)
    assert not worker.is_alive()


def test_verify_rejects_healthy_record_from_wrong_source():
    runner = ReadOnlyRunner("condonet-test")
    requested = runner.probes["resident-dns-udp"]
    wrong = replace(requested, source_node="admin")
    sample = ProbeResult.observed(wrong, "healthy", "dns_answer", {"container": "clab-condonet-test-admin"})
    runner.run = lambda _: sample
    ok, records = Verifier(runner).measure(((requested.id, "healthy"),))
    assert not ok and records[0]["source_node"] == "admin"


def test_interrupted_baseline_records_unexecuted_trial(tmp_path, monkeypatch):
    case = evaluation.slots()["r1-01"]
    monkeypatch.setattr(evaluation, "ROOT", tmp_path)
    args = SimpleNamespace(lab="condonet-day09-test", output=tmp_path, eve=None)
    runner = evaluation.Evaluation(args, None)
    runner.baseline = Mock(side_effect=KeyboardInterrupt)
    trial = evaluation.Trial("r1-01", case, tmp_path / "attempt", "attempt")
    result = runner.run(trial)
    assert runner.interrupted and result["verdict"] == "NOT RUN"
    assert json.loads((trial.directory / "trial.json").read_text())["row"] == result


def test_postcheck_failure_restores_snapshot_and_escalates(tmp_path):
    store = ApprovalStore(tmp_path / "approvals.sqlite")
    policy = RunnerPolicy("condonet-test")
    candidate = plan(runbook="RB02")
    ticket = issue(store, policy, candidate)
    store.review(candidate.incident_id, ticket.actor, ticket.plan_hash, True)
    claimed = store.claim(request_for(ticket), policy)
    state = {"process": "nginx", "status": "STOPPED", "pid": None,
             "configuration_sha256": candidate.configuration_sha256}
    actions = LabActions(policy)
    actions.prepare = lambda _: state.copy()
    actions.service_snapshot = lambda _: state.copy()

    def execute(_plan, operation, *args, **kwargs):
        state["status"] = {"start": "RUNNING", "stop": "STOPPED"}[operation]

    actions.run = execute
    check = Mock(spec=Verifier)
    check.precheck.return_value = True, []
    check.postcheck.return_value = False, []
    check.canaries.return_value = Verifier.CANARIES
    check.rollback_check.return_value = False, [
        {"probe_id": key, "status": "healthy"} for key in Verifier.CANARIES]
    ActionRunner(store, actions, check)(claimed)
    result = store.get(candidate.incident_id)
    audit = store.history(candidate.incident_id)
    assert result.status == "escalated" and state["status"] == "STOPPED"
    assert result.result["before"] == result.result["rollback"] == state
    assert result.result["after"]["status"] == "RUNNING"
    assert [row["event"] for row in audit] == [
        "pending", "approved", "claimed", "snapshot", "applied", "rollback_started", "escalated"]
    assert Counter(row["plan_hash"] for row in audit) == {ticket.plan_hash: len(audit)}
