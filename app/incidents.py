from dataclasses import asdict

from app.agent import Agent, Checkpoints
from app.incident_store import IncidentStore
from app.retrieval import RunbookRetriever
from runner.plans import preview, review_blockers
from runner.policy import PolicyDenied


ACTIVE = {"pending", "approved", "running", "open", "missing", "need_human", "escalated", "failed"}


class IncidentService:
    def __init__(self, path, approvals, policy, probes, model, operator):
        self.path = path
        self.approvals = approvals
        self.policy = policy
        self.probes = probes
        self.model = model
        self.operator = operator

    @staticmethod
    def summary(incident, ticket, state):
        if ticket:
            status = ticket.status
        elif state and state.error == "missing_evidence":
            status = "missing"
        elif state and state.phase in {"need_human", "diagnosed"}:
            status = state.phase
        else:
            status = incident.status
        return {**asdict(incident), "status": status, "collector_status": incident.status,
                "severity": "high" if incident.origin == "ids_test" or incident.service == "dns" else "medium",
                "needs_attention": status in ACTIVE}

    def list(self):
        with IncidentStore(self.path) as store:
            checkpoints = Checkpoints(store.connection)
            return sorted((self.summary(incident, self.approvals.get(incident.id),
                                        checkpoints.load(incident.id)) for incident in store.list_incidents()),
                          key=lambda row: (row["needs_attention"], row["timestamp"], row["id"]), reverse=True)

    @staticmethod
    def observations(store, incident, state):
        identifiers = dict.fromkeys((*incident.evidence_ids, *(state.evidence_ids if state else ()),
                                     *(state.decision.evidence_ids if state and state.decision else ())))
        return [item for key in identifiers if (item := store.get_evidence(key)) is not None]

    def detail(self, incident_id):
        with IncidentStore(self.path) as store:
            incident = store.get_incident(incident_id)
            if incident is None:
                return None
            state = Checkpoints(store.connection).load(incident_id)
            observations = sorted(self.observations(store, incident, state), key=lambda row: row.timestamp)
        ticket = self.approvals.get(incident_id)
        approval = ticket.record() if ticket else None
        proposal = preview(ticket.plan) if ticket else None
        evidence = [asdict(item) for item in observations]
        audit = self.approvals.history(incident_id)
        return {"incident": self.summary(incident, ticket, state), "evidence": evidence,
                "agent": state.model_dump(mode="json") if state else None,
                "proposal": proposal, "approval": approval, "audit": audit,
                "review_blockers": review_blockers(proposal, approval, evidence)}

    def investigate(self, incident_id):
        with IncidentStore(self.path) as store:
            incident = store.get_incident(incident_id)
            if incident is None:
                return None
            if self.approvals.get(incident_id) is None:
                retriever = RunbookRetriever(store.connection)
                retriever.load()
                state = Agent(self.probes, retriever, self.model, store).run(incident_id)
                try:
                    plan = self.policy.from_decision(incident, state, self.observations(store, incident, state))
                except PolicyDenied:
                    pass
                else:
                    self.approvals.issue(plan, self.operator, self.policy.validate(plan))
        return self.detail(incident_id)
