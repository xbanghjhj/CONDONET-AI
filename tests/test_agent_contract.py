import unittest

from pydantic import ValidationError

from app.schemas import AgentState, Decision, MAX_INVESTIGATIONS, ProbeRequest


def request():
    return {"probe_id": "resident-portal-http", "source_node": "resident", "target": "10.60.50.10:80"}


class SchemaTest(unittest.TestCase):
    def test_valid_schema_and_forbidden_fields(self):
        model = Decision(status="investigate", hypothesis="unknown", next_tool=ProbeRequest(**request()))
        self.assertEqual(model.next_tool.probe_id, "resident-portal-http")
        with self.assertRaises(ValidationError):
            Decision(status="need_human", hypothesis="unknown", command="id")
        with self.assertRaises(ValidationError):
            ProbeRequest(**request(), options={"extra": 1})

    def test_probe_source_target_and_id_are_checked(self):
        for overrides in ({"probe_id": "guest-portal-http"}, {"source_node": "admin"},
                          {"target": "192.0.2.10:80"}):
            with self.subTest(overrides=overrides), self.assertRaises(ValidationError):
                ProbeRequest(**{**request(), **overrides})

    def test_four_investigations_and_no_illegal_transition(self):
        initial = AgentState(incident_id="case-a")
        with self.assertRaises(ValueError):
            initial.investigation(ProbeRequest(**request()))
        state = initial.diagnosis()
        for number in range(1, MAX_INVESTIGATIONS + 1):
            state = state.investigation(ProbeRequest(**request()))
            self.assertEqual((state.phase, state.investigations), ("investigate", number))
            state = state.diagnosis()
        blocked = state.investigation(ProbeRequest(**request()))
        self.assertEqual((blocked.phase, blocked.error), ("need_human", "investigation_limit"))
        self.assertEqual(blocked.investigations, 4)


class FixedModel:
    def __init__(self, *answers):
        self.answers = iter(answers)
        self.calls = 0

    def decide(self, context):
        self.calls += 1
        answer = next(self.answers)
        if isinstance(answer, Exception):
            raise answer
        return answer


class AgentContractTest(unittest.TestCase):
    def setUp(self):
        from app.incident_store import Evidence, IncidentStore, StoredIncident
        from app.retrieval import RunbookRetriever

        self.store = IncidentStore(":memory:")
        self.addCleanup(self.store.connection.close)
        self.retriever = RunbookRetriever(self.store.connection)
        self.retriever.load()
        stamp = "2026-11-26T12:00:00+00:00"
        self.dns = Evidence("dns-id", stamp, "resident", "dns", "dns", "10.60.50.10:53",
                            "healthy", "dns_answer", {}, {"dns_success": 1}, "resident-dns-udp")
        self.web = Evidence("web-id", stamp, "resident", "portal", "http", "10.60.50.10:80",
                            "failed", "connection_failure", {}, {}, "resident-portal-http")
        self.incident = StoredIncident("web-case", stamp, "resident", "portal", "connection_failure",
                                       "diagnostic", (self.dns.id, self.web.id))
        self.store.save_incident(self.incident, (self.dns, self.web))

    def agent(self, model, runner=None, retriever=None):
        from app.agent import Agent
        return Agent(runner, retriever or self.retriever, model, self.store)

    def proposal(self, **overrides):
        fields = {"status": "propose", "hypothesis": "web_down", "evidence_ids": ["dns-id", "web-id"],
                  "runbook_id": "RB02", "runbook_version": "1.0.0", "target": "svc", "risk": "low"}
        return Decision(**{**fields, **overrides}).model_dump_json()

    def test_valid_proposal_and_checkpoint_resume(self):
        model = FixedModel(self.proposal())
        original = self.agent(model).run(self.incident.id)
        self.assertEqual(original.phase, "propose")
        self.assertEqual(self.agent(FixedModel()).run(self.incident.id), original)
        self.assertEqual(model.calls, 1)

    def test_reject_invented_evidence_and_unverified_runbook_version(self):
        for answer, reason in ((self.proposal(evidence_ids=["invented"]), "unverified_evidence_id"),
                               (self.proposal(runbook_version="2.0.0"), "unverified_runbook"),
                               (self.proposal(evidence_ids=["web-id"]), "insufficient_diagnostic_evidence"),
                               (self.proposal(target="gw"), "proposal_outside_scope")):
            with self.subTest(reason=reason):
                agent = self.agent(FixedModel(answer))
                with self.store.connection:
                    self.store.connection.execute("DELETE FROM agent_checkpoints")
                result = agent.run(self.incident.id)
                self.assertEqual((result.phase, result.error), ("need_human", reason))

    def test_invalid_json_gets_one_retry(self):
        model = FixedModel("{bad", '{"status":"unknown","command":"id"}', self.proposal())
        result = self.agent(model).run(self.incident.id)
        self.assertEqual((result.phase, result.error, result.invalid_retries, model.calls),
                         ("need_human", "invalid_model_output", 1, 2))

    def test_model_timeout_requires_human_without_retry(self):
        model = FixedModel(TimeoutError("deadline"))
        result = self.agent(model).run(self.incident.id)
        self.assertEqual((result.phase, result.error, result.invalid_retries, model.calls),
                         ("need_human", "model_timeout", 0, 1))

    def test_allowlisted_probe_for_other_source_still_rejected(self):
        from dataclasses import replace
        from unittest.mock import Mock

        runner = Mock()
        pending = replace(self.incident, id="needs-web-probe", evidence_ids=(self.dns.id,))
        self.store.save_incident(pending)
        tool = ProbeRequest(probe_id="admin-portal-http", source_node="admin", target="10.60.50.10:80")
        answer = Decision(status="investigate", hypothesis="unknown", next_tool=tool).model_dump_json()
        result = self.agent(FixedModel(answer), runner=runner).run(pending.id)
        self.assertEqual(result.error, "probe_outside_scope")
        runner.run.assert_not_called()

    def test_missing_evidence_and_missing_runbook_require_human(self):
        from unittest.mock import Mock
        from dataclasses import replace

        empty = replace(self.incident, id="empty-case", evidence_ids=())
        self.store.save_incident(empty)
        self.assertEqual(self.agent(FixedModel()).run(empty.id).error, "missing_evidence")
        retriever = Mock()
        retriever.search.return_value = []
        self.assertEqual(self.agent(FixedModel(), retriever=retriever).run(self.incident.id).error,
                         "missing_runbook")
