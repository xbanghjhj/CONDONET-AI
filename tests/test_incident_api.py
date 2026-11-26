import json

from fastapi.testclient import TestClient

from app.api import ApiSettings, create_app
from app.approvals import ApprovalStore
from app.incident_store import Evidence, IncidentStore, StoredIncident


class ObservedModel:
    def decide(self, context):
        return json.dumps(context["options"]["propose-RB02-1.0.0"])


def seed_incidents(path):
    stamp = "2026-11-27T03:00:00+00:00"
    dns = Evidence("good-dns", stamp, "resident", "dns", "dns", "10.60.50.10:53",
                   "healthy", "dns_answer", {}, {"dns_success": 1}, "resident-dns-udp")
    web = Evidence("bad-web", stamp, "resident", "portal", "http", "10.60.50.10:80",
                   "failed", "connection_failure", {}, {}, "resident-portal-http")
    case = StoredIncident("portal-1", stamp, "resident", "portal", "connection_failure",
                          "collector", (dns.id, web.id))
    with IncidentStore(path) as store:
        store.save_incident(case, (dns, web))
        store.save_incident(StoredIncident("missing-1", stamp, "resident", "portal", "missing",
                                           "diagnostic", ()))
    return case


def test_incident_routes_preserve_sqlite_state_and_review_authority(tmp_path):
    path = tmp_path / "old-state.sqlite"
    case = seed_incidents(path)
    settings = ApiSettings(tmp_path / "approvals.sqlite", tmp_path / "runner.sock", "operator",
                           "fixture", path)
    headers = {"Authorization": "Bearer fixture"}
    with TestClient(create_app(settings, ObservedModel())) as api:
        assert api.get("/health").json()["status"] == "ok"
        assert len(api.get("/topology").json()["hosts"]) == 5
        assert len(api.get("/incidents").json()) == 2
        assert api.get("/incidents/unknown").status_code == 404
        assert api.get("/incidents/@invalid").status_code == 422
        endpoint = f"/incidents/{case.id}"
        assert api.post(f"{endpoint}/investigate").status_code == 401
        assert api.get(endpoint).json()["incident"]["status"] == "open"
        detail = api.post(f"{endpoint}/investigate", headers=headers).json()
        assert detail["incident"]["status"] == "pending" and not detail["review_blockers"]
        assert detail["proposal"]["plan"]["runbook_id"] == "RB02"
        assert {row["id"] for row in detail["evidence"]} == set(case.evidence_ids)
        action = api.get(f"{endpoint}/action").json()
        assert action["approval"] == ApprovalStore(settings.approval_db).get(case.id).record()
        assert api.post(f"{endpoint}/approve", headers=headers, json={"plan_hash": "0" * 64}).status_code == 409
        assert api.post(f"{endpoint}/reject", headers=headers,
                        json={"plan_hash": action["approval"]["plan_hash"]}).json()["status"] == "rejected"
        missing = api.post("/incidents/missing-1/investigate", headers=headers).json()
        assert missing["incident"]["status"] == "missing" and missing["approval"] is None
    with TestClient(create_app(settings, ObservedModel())) as restarted:
        assert restarted.get(endpoint).json()["incident"]["status"] == "rejected"
        assert restarted.get("/incidents/missing-1").json()["agent"]["error"] == "missing_evidence"
