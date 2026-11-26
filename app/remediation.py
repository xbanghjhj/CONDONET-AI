from app.approvals import ApprovalConflict


class RunnerUnavailable(RuntimeError):
    pass


class RemediationService:
    def __init__(self, approvals, action_client, incidents=None):
        self.approvals = approvals
        self.action_client = action_client
        self.incidents = incidents

    def review(self, incident_id, operator, plan_hash, approve):
        if self.incidents is not None:
            detail = self.incidents.detail(incident_id)
            if detail is None:
                return None
            approval = detail["approval"]
            if (approve and approval and approval["status"] in {"pending", "approved"}
                    and detail["review_blockers"]):
                raise ApprovalConflict(detail["review_blockers"])

        ticket = self.approvals.review(incident_id, operator, plan_hash, approve)
        if approve and ticket.status == "approved":
            try:
                self.action_client.submit(ticket)
            except OSError as error:
                raise RunnerUnavailable("Approval recorded, runner unavailable") from error
            ticket = self.approvals.get(incident_id)
            if ticket.status == "approved":
                raise ApprovalConflict("Approval recorded, runner could not claim the target")
        return ticket
