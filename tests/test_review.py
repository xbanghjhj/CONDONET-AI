from dataclasses import asdict
from datetime import datetime, timezone

from streamlit.testing.v1 import AppTest

from app.approvals import ApprovalStore
from app.incident_store import Evidence, IncidentStore, StoredIncident
from app.schemas import RemediationPlan
from runner.plans import RUNBOOKS, preview, review_blockers


def review_screen(proposal, record, evidence, now):
    from ui.review import review_controls

    review_controls(proposal, record, evidence, now)


def test_review_requires_evidence_and_complete_unexpired_plan(tmp_path):
    row = Evidence("probe-1", "2026-11-27T03:00:00+00:00", "resident", "dns", "dns",
                   "10.60.50.10:53", "failed", "dns_unreachable", {}, {"dns_success": 0})
    incident = StoredIncident("dns-1", row.timestamp, "resident", "dns", row.reason, "collector", (row.id,))
    path = tmp_path / "incidents.sqlite"
    with IncidentStore(path) as store:
        store.save_incident(incident, [row])
    with IncidentStore(path) as store:
        selected = store.get_incident("dns-1")
        evidence = [asdict(store.get_evidence(key)) for key in selected.evidence_ids]
    plan = RemediationPlan(incident_id=selected.id, runbook_id="RB01", runbook_version="1.0.0",
                           target="svc", source_node=selected.source_node, evidence_ids=selected.evidence_ids,
                           configuration_sha256=RUNBOOKS["RB01"].configuration_sha256)
    now = datetime.fromisoformat(row.timestamp)
    approvals = ApprovalStore(tmp_path / "approvals.sqlite", clock=now.timestamp)
    record = approvals.issue(plan, "operator", "svc").record()
    proposal = preview(plan)
    assert not review_blockers(proposal, record, evidence, now)
    assert review_blockers(proposal, record, [], now)
    for field in ("change", "impact", "rollback", "verify", "approval_ttl_seconds"):
        assert review_blockers({key: value for key, value in proposal.items() if key != field},
                               record, evidence, now)
    assert review_blockers(proposal, {**record, "plan_hash": "0" * 64}, evidence, now)
    assert review_blockers(proposal, record, evidence,
                           datetime.fromtimestamp(now.timestamp() + 300, timezone.utc))
    ready = AppTest.from_function(review_screen, args=(proposal, record, evidence, now)).run()
    blocked = AppTest.from_function(review_screen, args=(proposal, record, [], now)).run()
    assert not ready.exception and not ready.button(key="approve").disabled
    assert not blocked.exception and blocked.button(key="approve").disabled
