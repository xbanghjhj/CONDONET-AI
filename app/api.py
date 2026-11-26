import argparse
import os
from dataclasses import dataclass
from pathlib import Path
from secrets import compare_digest
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.approvals import ApprovalConflict, ApprovalStore, Review
from app.schemas import Identifier
from runner.action_socket import ActionClient


@dataclass(frozen=True)
class ApiSettings:
    approval_db: Path
    action_socket: Path
    operator: str
    token: str


def create_app(settings):
    if not settings.token:
        raise ValueError("A local operator token is required")
    app = FastAPI()
    approvals = ApprovalStore(settings.approval_db)
    action_client = ActionClient(settings.action_socket)
    bearer = HTTPBearer(auto_error=False)

    def actor(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]):
        if credentials is None or not compare_digest(credentials.credentials.encode(), settings.token.encode()):
            raise HTTPException(401, "Valid local operator token required", {"WWW-Authenticate": "Bearer"})
        return settings.operator

    def review(incident_id, body, operator, approve):
        try:
            ticket = approvals.review(incident_id, operator, body.plan_hash, approve)
        except ApprovalConflict as error:
            raise HTTPException(409, str(error)) from error
        if approve and ticket.status == "approved":
            try:
                action_client.submit(ticket)
            except OSError:
                raise HTTPException(503, "Approval recorded, runner unavailable") from None
            ticket = approvals.get(incident_id)
            if ticket.status == "approved":
                raise HTTPException(409, "Approval recorded, runner could not claim the target")
        return ticket.record()

    @app.post("/incidents/{incident_id}/approve")
    def approve_incident(incident_id: Identifier, body: Review, operator: Annotated[str, Depends(actor)]):
        return review(incident_id, body, operator, True)

    @app.post("/incidents/{incident_id}/reject")
    def reject_incident(incident_id: Identifier, body: Review, operator: Annotated[str, Depends(actor)]):
        return review(incident_id, body, operator, False)

    return app


def main():
    import uvicorn

    parser = argparse.ArgumentParser(description="Serve local CondoNet operator endpoints.")
    parser.add_argument("--approval-db", required=True, type=Path)
    parser.add_argument("--action-socket", required=True, type=Path)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    privileges = Path("/proc/self/status").read_text()
    if (os.geteuid() == 0 or "\nNoNewPrivs:\t1\n" not in privileges
            or os.access("/var/run/docker.sock", os.W_OK)):
        parser.error("Run the API as a non-Docker user with setpriv --no-new-privs")
    settings = ApiSettings(args.approval_db, args.action_socket, args.operator,
                           os.environ.get("CONDONET_OPERATOR_TOKEN", ""))
    uvicorn.run(create_app(settings), host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
