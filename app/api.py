import argparse
import os
from dataclasses import asdict, dataclass
from http.client import HTTPConnection
from pathlib import Path
from secrets import compare_digest
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.agent import OLLAMA_MODEL, OllamaModel
from app.approvals import ApprovalConflict, ApprovalStore, Review
from app.incidents import IncidentService
from app.metrics import METRICS_ADDRESS
from app.remediation import RemediationService, RunnerUnavailable
from app.schemas import PROBE_TIMEOUT, Identifier
from lab.topology import HOSTS, WAN_ADDRESS
from runner.action_socket import ActionClient
from runner.policy import RunnerPolicy
from runner.probe_socket import ProbeClient


@dataclass(frozen=True)
class ApiSettings:
    approval_db: Path
    action_socket: Path
    operator: str
    token: str
    incident_db: Path | None = None
    probe_socket: Path | None = None
    lab: str = "condonet"
    model: str = OLLAMA_MODEL


def create_app(settings, model=None):
    if not settings.token:
        raise ValueError("A local operator token is required")
    app = FastAPI()
    approvals = ApprovalStore(settings.approval_db)
    bearer = HTTPBearer(auto_error=False)
    service = None
    if settings.incident_db is not None:
        probes = ProbeClient(settings.probe_socket, PROBE_TIMEOUT) if settings.probe_socket else None
        service = IncidentService(settings.incident_db, approvals, RunnerPolicy(settings.lab),
                                  probes, model or OllamaModel(settings.model), settings.operator)
    remediation = RemediationService(approvals, ActionClient(settings.action_socket), service)

    def actor(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]):
        if credentials is None or not compare_digest(credentials.credentials.encode(), settings.token.encode()):
            raise HTTPException(401, "Valid local operator token required", {"WWW-Authenticate": "Bearer"})
        return settings.operator

    def review(incident_id, body, operator, approve):
        try:
            ticket = remediation.review(incident_id, operator, body.plan_hash, approve)
        except ApprovalConflict as error:
            raise HTTPException(409, error.args[0]) from error
        except RunnerUnavailable as error:
            raise HTTPException(503, str(error)) from error
        if ticket is None:
            raise HTTPException(404, "Incident not found")
        return ticket.record()

    @app.post("/incidents/{incident_id}/approve")
    def approve_incident(incident_id: Identifier, body: Review, operator: Annotated[str, Depends(actor)]):
        return review(incident_id, body, operator, True)

    @app.post("/incidents/{incident_id}/reject")
    def reject_incident(incident_id: Identifier, body: Review, operator: Annotated[str, Depends(actor)]):
        return review(incident_id, body, operator, False)

    def incident_service():
        if service is None:
            raise HTTPException(503, "Incident database is unavailable")
        return service

    @app.get("/health")
    def health():
        return {"status": "ok", "lab": settings.lab}

    @app.get("/topology")
    def topology():
        return {"lab": settings.lab, "hosts": [asdict(host) | {"gateway": host.gateway} for host in HOSTS],
                "wan": WAN_ADDRESS}

    @app.get("/incidents")
    def incidents():
        return incident_service().list()

    @app.get("/incidents/{incident_id}")
    def incident_detail(incident_id: Identifier):
        detail = incident_service().detail(incident_id)
        if detail is None:
            raise HTTPException(404, "Incident not found")
        return detail

    @app.post("/incidents/{incident_id}/investigate", dependencies=[Depends(actor)])
    def investigate(incident_id: Identifier):
        detail = incident_service().investigate(incident_id)
        if detail is None:
            raise HTTPException(404, "Incident not found")
        return detail

    @app.get("/incidents/{incident_id}/action")
    def action_status(incident_id: Identifier):
        detail = incident_detail(incident_id)
        return {"approval": detail["approval"], "audit": detail["audit"]}

    @app.get("/metrics")
    def metrics():
        connection = HTTPConnection(*METRICS_ADDRESS, timeout=2)
        try:
            connection.request("GET", "/metrics")
            response = connection.getresponse()
            if response.status != 200:
                raise HTTPException(503, "Collector metrics are unavailable")
            return Response(response.read(), headers={"Content-Type": response.getheader("Content-Type")})
        except OSError:
            raise HTTPException(503, "Collector metrics are unavailable") from None
        finally:
            connection.close()

    return app


def main():
    import uvicorn

    parser = argparse.ArgumentParser(description="Serve local CondoNet operator endpoints.")
    parser.add_argument("--approval-db", required=True, type=Path)
    parser.add_argument("--action-socket", required=True, type=Path)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--incident-db", type=Path)
    parser.add_argument("--probe-socket", type=Path)
    parser.add_argument("--lab", default="condonet")
    parser.add_argument("--model", default=OLLAMA_MODEL)
    args = parser.parse_args()
    privileges = Path("/proc/self/status").read_text()
    if (os.geteuid() == 0 or "\nNoNewPrivs:\t1\n" not in privileges
            or os.access("/var/run/docker.sock", os.W_OK)):
        parser.error("Run the API as a non-Docker user with setpriv --no-new-privs")
    settings = ApiSettings(args.approval_db, args.action_socket, args.operator,
                           os.environ.get("CONDONET_OPERATOR_TOKEN", ""), args.incident_db,
                           args.probe_socket, args.lab, args.model)
    uvicorn.run(create_app(settings), host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
