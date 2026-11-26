from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path


APPROVAL_TTL_SECONDS = 300
QUARANTINE_TTL_SECONDS = 120
CONFIG_DIRECTORY = Path(__file__).resolve().parents[1] / "configs"


@dataclass(frozen=True)
class Runbook:
    hypothesis: str
    process: str | None
    configuration: str | None
    mounted_path: str | None
    precheck: str
    impact: str
    verify: str
    rollback: str

    @property
    def configuration_sha256(self):
        if self.configuration is not None:
            return sha256((CONFIG_DIRECTORY / self.configuration).read_bytes()).hexdigest()
        return None


RUNBOOKS = {
    "RB01": Runbook(
        "dns_failure", "dns", "dns/dnsmasq.conf", "/condonet/dns.conf",
        "Confirm lab DNS fails, the portal works by IP and the mounted dnsmasq config passes validation.",
        "Restart only the DNS service on svc. DNS queries may briefly fail.",
        "Check DNS over UDP and TCP, portal by name, and two unaffected VLAN canaries.",
        "Restore the previous DNS process state and confirm the configuration digest and canaries.",
    ),
    "RB02": Runbook(
        "web_down", "nginx", "nginx/nginx.conf", "/condonet/nginx.conf",
        "Confirm DNS works, the portal fails by IP and the mounted Nginx config passes its syntax check.",
        "Restart only the portal Nginx process on svc. In-flight portal requests may fail.",
        "Check the HTTP status and portal body, and two unaffected VLAN canaries.",
        "Restore the previous Nginx process state and confirm the configuration digest and canaries.",
    ),
    "RB03": Runbook(
        "ids_test", None, None, None,
        "Match a validated EVE alert to the current lab source address and verify it can reach the portal.",
        "Block routed traffic for the single EVE source in the lab quarantine set for 120 seconds.",
        "Confirm source isolation, two unaffected VLAN canaries and automatic expiry.",
        "Remove only the added source element and verify the previous connectivity.",
    ),
}


def preview(plan):
    runbook = RUNBOOKS[plan.runbook_id]
    parameters = plan.parameters
    if runbook.process:
        change = {"resource": runbook.process, "before": "service probe failed",
                  "after": "running with validated standard configuration",
                  "configuration_sha256": plan.configuration_sha256}
    else:
        change = {"resource": f"quarantine/{parameters.source_ipv4}", "before": "absent",
                  "after": f"present for {parameters.ttl_seconds} seconds"}
    return {
        "plan": plan.model_dump(mode="json"),
        "plan_hash": plan.digest,
        "change": change,
        "precheck": runbook.precheck,
        "impact": runbook.impact,
        "verify": runbook.verify,
        "rollback": runbook.rollback,
        "approval_ttl_seconds": APPROVAL_TTL_SECONDS,
    }


def review_blockers(proposal, approval, evidence, now=None):
    if not proposal or not approval:
        return ["Chưa có đề xuất chờ xử lý"]
    blockers = []
    plan = proposal.get("plan", {})
    if not all(plan.get(field) for field in ("runbook_id", "runbook_version", "target")):
        blockers.append("Thiếu runbook, phiên bản hoặc đích")
    change = proposal.get("change", {})
    if not all(change.get(field) for field in ("resource", "before", "after")):
        blockers.append("Thiếu thay đổi dự kiến")
    if not all(proposal.get(field) for field in ("impact", "rollback", "verify", "approval_ttl_seconds")):
        blockers.append("Thiếu tác động, thời hạn, xác minh hoặc rollback")
    active_evidence = {row["id"] for row in evidence if row.get("id") and row.get("status") != "missing"}
    if not plan.get("evidence_ids") or not set(plan["evidence_ids"]) <= active_evidence:
        blockers.append("Thiếu bằng chứng của đề xuất")
    if not proposal.get("plan_hash") or approval.get("plan_hash") != proposal["plan_hash"]:
        blockers.append("Hash đề xuất không khớp approval")
    if approval.get("status") not in {"pending", "approved"}:
        blockers.append("Approval đã đóng")
    try:
        expiration = datetime.fromisoformat(approval.get("expires_at", ""))
        if expiration <= (now or datetime.now(timezone.utc)):
            blockers.append("Approval đã hết hạn")
    except (TypeError, ValueError):
        blockers.append("Thiếu thời điểm hết hạn")
    return blockers
