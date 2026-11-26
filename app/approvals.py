import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from time import time
from uuid import uuid4

from app.schemas import Contract, Digest, Identifier, RemediationPlan
from runner.plans import APPROVAL_TTL_SECONDS


class ApprovalConflict(ValueError):
    pass


class Review(Contract):
    plan_hash: Digest


class ClaimRequest(Review):
    approval_id: Identifier
    incident_id: Identifier
    actor: Identifier


@dataclass(frozen=True)
class Ticket:
    id: str
    actor: str
    plan: RemediationPlan
    plan_hash: str
    expires_at: float
    status: str
    result: dict | None

    def record(self):
        return {"id": self.id, "actor": self.actor, "plan_hash": self.plan_hash,
                "expires_at": utc(self.expires_at), "status": self.status, "result": self.result}


def utc(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="milliseconds")


class ApprovalStore:
    def __init__(self, path, clock=time):
        self.path = path
        self.clock = clock
        with self.transaction() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS remediation_approvals (
                id TEXT PRIMARY KEY, incident_id TEXT NOT NULL UNIQUE, actor TEXT NOT NULL,
                plan TEXT NOT NULL, plan_hash TEXT NOT NULL, resource TEXT NOT NULL,
                expires_at REAL NOT NULL, status TEXT NOT NULL, result TEXT)""")
            connection.execute("""CREATE UNIQUE INDEX IF NOT EXISTS remediation_running_target
                ON remediation_approvals(resource) WHERE status = 'running'""")
            connection.execute("""CREATE TABLE IF NOT EXISTS remediation_audit (
                sequence INTEGER PRIMARY KEY, incident_id TEXT NOT NULL, record TEXT NOT NULL)""")
            connection.execute("""CREATE INDEX IF NOT EXISTS remediation_audit_incident
                ON remediation_audit(incident_id, sequence)""")

    @contextmanager
    def transaction(self):
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
        finally:
            connection.close()

    @staticmethod
    def ticket(row):
        if row is None:
            return None
        return Ticket(row["id"], row["actor"], RemediationPlan.model_validate_json(row["plan"]),
                      row["plan_hash"], row["expires_at"], row["status"],
                      json.loads(row["result"]) if row["result"] else None)

    @staticmethod
    def lookup(connection, incident_id):
        return connection.execute("SELECT * FROM remediation_approvals WHERE incident_id = ?",
                                  (incident_id,)).fetchone()

    def audit(self, connection, ticket, event, details=None):
        plan = ticket.plan
        record = {"event": event, "utc": utc(self.clock()), "actor": ticket.actor,
                  "approval_id": ticket.id, "incident_id": plan.incident_id,
                  "action": plan.runbook_id, "target": plan.target,
                  "evidence_ids": plan.evidence_ids, "plan_hash": ticket.plan_hash,
                  "parameters": plan.parameters.model_dump(mode="json"), "details": details}
        connection.execute("INSERT INTO remediation_audit (incident_id, record) VALUES (?, ?)",
                           (plan.incident_id, json.dumps(record)))

    def expire(self, connection, row):
        if row and row["status"] in {"pending", "approved"} and self.clock() >= row["expires_at"]:
            connection.execute("UPDATE remediation_approvals SET status = 'expired' WHERE id = ?", (row["id"],))
            self.audit(connection, self.ticket(row), "expired")
            return self.lookup(connection, row["incident_id"])
        return row

    def issue(self, plan, actor, resource):
        with self.transaction() as connection:
            row = self.expire(connection, self.lookup(connection, plan.incident_id))
            if row is None:
                connection.execute("""INSERT INTO remediation_approvals
                    (id, incident_id, actor, plan, plan_hash, resource, expires_at, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')""",
                    (uuid4().hex, plan.incident_id, actor, plan.model_dump_json(), plan.digest, resource,
                     self.clock() + APPROVAL_TTL_SECONDS))
                row = self.lookup(connection, plan.incident_id)
                self.audit(connection, self.ticket(row), "pending")
        return self.ticket(row)

    def get(self, incident_id):
        with self.transaction() as connection:
            return self.ticket(self.expire(connection, self.lookup(connection, incident_id)))

    def review(self, incident_id, actor, plan_hash, approve):
        status = "approved" if approve else "rejected"
        with self.transaction() as connection:
            row = self.expire(connection, self.lookup(connection, incident_id))
            ticket = self.ticket(row)
            if ticket and (ticket.actor, ticket.plan_hash, ticket.plan.digest) == (actor, plan_hash, plan_hash):
                if ticket.status == "pending":
                    connection.execute("UPDATE remediation_approvals SET status = ? WHERE id = ?",
                                       (status, ticket.id))
                    self.audit(connection, ticket, status)
                    return self.ticket(self.lookup(connection, incident_id))
                if ticket.status == status or (approve and ticket.status in {
                        "running", "verified", "failed", "rolled_back", "escalated"}):
                    return ticket
        raise ApprovalConflict("Approval is missing, expired, or bound to another actor or plan")

    def claim(self, request, policy):
        with self.transaction() as connection:
            row = self.expire(connection, self.lookup(connection, request.incident_id))
            ticket = self.ticket(row)
            if ticket and (ticket.id, ticket.actor, ticket.plan_hash, ticket.plan.digest, ticket.status) == (
                    request.approval_id, request.actor, request.plan_hash, request.plan_hash, "approved"):
                resource = policy.validate(ticket.plan)
                if resource != row["resource"]:
                    raise ApprovalConflict("Approval resource does not match the allowlist")
                busy = connection.execute("""SELECT 1 FROM remediation_approvals
                    WHERE resource = ? AND status = 'running'""", (resource,)).fetchone()
                if not busy:
                    connection.execute("UPDATE remediation_approvals SET status = 'running' WHERE id = ?",
                                       (ticket.id,))
                    self.audit(connection, ticket, "claimed")
                    return self.ticket(self.lookup(connection, request.incident_id))
        raise ApprovalConflict("Approval cannot be claimed or target is busy")

    def history(self, incident_id):
        with self.transaction() as connection:
            return [json.loads(row[0]) for row in connection.execute(
                "SELECT record FROM remediation_audit WHERE incident_id = ? ORDER BY sequence", (incident_id,))]

    def record_progress(self, ticket, event, details):
        with self.transaction() as connection:
            self.require_running(connection, ticket)
            self.audit(connection, ticket, event, details)

    def finish(self, ticket, status, result):
        with self.transaction() as connection:
            self.require_running(connection, ticket)
            connection.execute("UPDATE remediation_approvals SET status = ?, result = ? WHERE id = ?",
                               (status, json.dumps(result), ticket.id))
            self.audit(connection, ticket, status, result)

    def require_running(self, connection, ticket):
        row = self.lookup(connection, ticket.plan.incident_id)
        if row is None or (row["id"], row["status"]) != (ticket.id, "running"):
            raise ApprovalConflict("Action no longer holds the target lock")
