import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from ipaddress import IPv4Address
from threading import Barrier, Event, Thread

import pytest
from fastapi.testclient import TestClient

from app.api import ApiSettings, create_app
from app.approvals import ApprovalConflict, ApprovalStore, ClaimRequest
from app.eve_ingest import EveParser
from app.schemas import AgentState, Decision, Parameters, RemediationParameters, RemediationPlan
from runner.action_socket import ActionServer
from runner.plans import RUNBOOKS
from runner.policy import PolicyDenied, RunnerPolicy


def plan(incident_id="incident-1", runbook="RB01", **changes):
    fields = {"incident_id": incident_id, "runbook_id": runbook, "runbook_version": "1.0.0",
              "target": "svc", "source_node": "resident", "evidence_ids": ("observed-1",),
              "configuration_sha256": RUNBOOKS[runbook].configuration_sha256}
    fields.update(changes)
    return RemediationPlan(**fields)


def request_for(ticket, **changes):
    fields = {"approval_id": ticket.id, "incident_id": ticket.plan.incident_id,
              "actor": ticket.actor, "plan_hash": ticket.plan_hash}
    fields.update(changes)
    return ClaimRequest(**fields)


def issue(store, policy, candidate=None):
    candidate = candidate or plan()
    return store.issue(candidate, "operator", policy.validate(candidate))


def test_actor_plan_id_rejection_and_expiry(tmp_path):
    now = [100.0]
    store = ApprovalStore(tmp_path / "approvals.sqlite", clock=lambda: now[0])
    policy = RunnerPolicy("condonet-test")
    ticket = issue(store, policy)
    assert ticket.expires_at == 400
    with pytest.raises(ApprovalConflict):
        store.claim(request_for(ticket), policy)
    with pytest.raises(ApprovalConflict):
        store.review(ticket.plan.incident_id, "someone-else", ticket.plan_hash, True)
    with pytest.raises(ApprovalConflict):
        store.review(ticket.plan.incident_id, ticket.actor, "f" * 64, True)
    store.review(ticket.plan.incident_id, ticket.actor, ticket.plan_hash, True)
    for changes in ({"actor": "someone-else"}, {"approval_id": "different"},
                    {"incident_id": "different"}, {"plan_hash": "f" * 64}):
        with pytest.raises(ApprovalConflict):
            store.claim(request_for(ticket, **changes), policy)
    now[0] = 400
    with pytest.raises(ApprovalConflict):
        store.claim(request_for(ticket), policy)
    assert store.get(ticket.plan.incident_id).status == "expired"
    second = issue(store, policy, plan("incident-2"))
    assert store.review(second.plan.incident_id, second.actor, second.plan_hash, False).status == "rejected"
    with pytest.raises(ApprovalConflict):
        store.claim(request_for(second), policy)


def test_single_claim_and_target_lock(tmp_path):
    store = ApprovalStore(tmp_path / "approvals.sqlite")
    policy = RunnerPolicy("condonet-test")
    first = issue(store, policy)
    second = issue(store, policy, plan("incident-2", "RB02"))
    for ticket in (first, second):
        store.review(ticket.plan.incident_id, ticket.actor, ticket.plan_hash, True)
    barrier = Barrier(3)

    def claim(ticket):
        barrier.wait()
        try:
            return store.claim(request_for(ticket), policy)
        except ApprovalConflict:
            return None

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(claim, (first, first, second)))
    assert sum(result is not None for result in results) == 1
    assert sum(store.get(ticket.plan.incident_id).status == "running" for ticket in (first, second)) == 1


def test_fixed_commands_and_policy_scope():
    policy = RunnerPolicy("condonet-test")
    dns = plan()
    assert policy.argv(dns, "restart") == ("docker", "exec", "--env", "LC_ALL=C",
                                          "clab-condonet-test-svc", "supervisorctl", "restart", "dns")
    quarantine = plan(runbook="RB03", target="resident",
                      parameters=RemediationParameters(source_ipv4=IPv4Address("10.60.20.10"),
                                                       ttl_seconds=120))
    assert policy.argv(quarantine, "add", "b" * 32)[-11:] == (
        "element", "ip", "condonet", "quarantine", "{", "10.60.20.10", "timeout", "120s",
        "comment", '"condonet-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"', "}")
    for invalid in (plan(target="wan"), quarantine.model_copy(update={
            "parameters": RemediationParameters(source_ipv4=IPv4Address("10.60.10.10"), ttl_seconds=120)
    }), quarantine.model_copy(update={
            "parameters": RemediationParameters(source_ipv4=IPv4Address("10.60.20.10"), ttl_seconds=119)
    })):
        with pytest.raises(PolicyDenied):
            policy.validate(invalid)
    with pytest.raises(PolicyDenied):
        policy.argv(dns, "shell")


def test_quarantine_requires_the_ingested_incident_evidence():
    alert = {"timestamp": "2026-11-26T19:00:00+00:00", "event_type": "alert", "flow_id": 42,
             "src_ip": "10.60.20.144", "src_port": 50700, "dest_ip": "10.60.50.10",
             "dest_port": 80, "proto": "TCP", "in_iface": "eth1", "vlan": [20],
             "alert": {"signature_id": 1000001, "action": "allowed"}, "http": {"url": "/lab-alert"}}
    incident, item = EveParser(["0 02:00:00:00:00:01 10.60.20.144 resident *"]).parse(json.dumps(alert))
    decision = Decision(status="propose", hypothesis="ids_test", runbook_id="RB03", target="resident",
                        runbook_version="1.0.0", parameters=Parameters(ttl_seconds=120),
                        evidence_ids=[item.id])
    state = AgentState(incident_id=incident.id, phase="propose", decision=decision)
    policy = RunnerPolicy("condonet-test")
    assert str(policy.from_decision(incident, state, [item]).parameters.source_ipv4) == "10.60.20.144"
    for evidence in ([], [replace(item, evidence={**item.evidence, "src_ip": "192.0.2.1"})],
                     [replace(item, evidence={**item.evidence, "vlan": 10})]):
        with pytest.raises(PolicyDenied):
            policy.from_decision(incident, state, evidence)
    with pytest.raises(PolicyDenied):
        policy.from_decision(replace(incident, evidence_ids=()), state, [item])


def test_approval_api_and_real_socket_only_dispatch_once(tmp_path):
    policy = RunnerPolicy("condonet-test")
    db = tmp_path / "approvals.sqlite"
    path = tmp_path / "remediation.sock"
    store = ApprovalStore(db)
    ticket = issue(store, policy)
    settings = ApiSettings(db, path, ticket.actor, "test-token")
    received = []
    done = Event()
    url = "/incidents/incident-1/approve"
    body = {"plan_hash": ticket.plan_hash}
    headers = {"Authorization": "Bearer test-token"}

    def record(claimed):
        received.append(claimed)
        done.set()

    with TestClient(create_app(settings)) as api:
        offline = api.post(url, json=body, headers=headers)
        assert offline.status_code == 503
        assert offline.json()["detail"] == "Approval recorded, runner unavailable"
        assert store.get(ticket.plan.incident_id).status == "approved"

    with ActionServer(path, store, policy, record, api_uid=os.getuid()) as server:
        assert path.stat().st_mode & 0o777 == 0o600
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with TestClient(create_app(replace(settings, operator="other"))) as wrong_actor:
                assert wrong_actor.post(url, json=body, headers=headers).status_code == 409
            with TestClient(create_app(settings)) as api:
                assert api.post(url, json=body).status_code == 401
                assert api.post(url, json={**body, "actor": "operator"}, headers=headers).status_code == 422
                assert api.post(url, json={"plan_hash": "0" * 64}, headers=headers).status_code == 409
                assert api.post(url, json=body, headers=headers).json()["status"] == "running"
                assert api.post(url, json=body, headers=headers).json()["status"] == "running"
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                    peer.connect(str(path))
                    peer.sendall(b'{"argv":["sh"]}\n')
                    assert peer.makefile("rb").readline() == b'{"status":"denied"}\n'
            assert done.wait(1)
            assert received == [store.get(ticket.plan.incident_id)]
        finally:
            server.shutdown()
            worker.join()
    assert not path.exists()
