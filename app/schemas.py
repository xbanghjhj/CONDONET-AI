import json
from functools import cache
from hashlib import sha256
from ipaddress import IPv4Address
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from runner.read_tools import policy_probes

MAX_INVESTIGATIONS = 4
PROBE_TIMEOUT = 8
MODEL_TIMEOUT = 120
Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{1,96}$")]
Node = Literal["admin", "resident", "guest", "camera", "svc", "gw", "wan", "sw"]
RunbookID = Literal["RB01", "RB02", "RB03", "RB04", "RB05", "RB06"]
Hypothesis = Literal["dns_failure", "web_down", "gateway_unreachable", "expected_deny",
                     "ids_test", "dhcp_failure", "packet_loss", "unknown"]
Phase = Literal["collect", "diagnose", "investigate", "propose", "diagnosed", "need_human"]
RemediationID = Literal["RB01", "RB02", "RB03"]
Version = Annotated[str, Field(pattern=r"^\d+\.\d+\.\d+$")]
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


@cache
def known_probes():
    return policy_probes()


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ProbeRequest(Contract):
    probe_id: Identifier
    source_node: Node
    target: Annotated[str, Field(max_length=80)]

    @model_validator(mode="after")
    def approved_probe(self):
        probe = known_probes().get(self.probe_id)
        if probe is None or (self.source_node, self.target) != (probe.source_node, probe.target):
            raise ValueError("Probe, source and target must match an allowlisted action")
        return self


class Parameters(Contract):
    ttl_seconds: Literal[120] | None = None


class Decision(Contract):
    status: Literal["investigate", "propose", "diagnosed", "need_human"]
    hypothesis: Hypothesis
    evidence_ids: list[Identifier] = Field(default_factory=list, max_length=16)
    missing_evidence: list[Annotated[str, Field(max_length=120)]] = Field(default_factory=list, max_length=8)
    next_tool: ProbeRequest | None = None
    runbook_id: RunbookID | None = None
    runbook_version: Version | None = None
    target: Node | None = None
    parameters: Parameters = Field(default_factory=Parameters)
    risk: Literal["none", "low", "medium"] = "none"

    @model_validator(mode="after")
    def validate_phase_fields(self):
        proposal = (self.runbook_id, self.runbook_version, self.target)
        if (self.next_tool is not None) != (self.status == "investigate"):
            raise ValueError("Only an investigation carries a next tool")
        if self.status == "propose":
            if not all(proposal) or not self.evidence_ids:
                raise ValueError("Proposal requires a versioned runbook, target and evidence")
            if (self.parameters.ttl_seconds == 120) != (self.runbook_id == "RB03"):
                raise ValueError("Only RB03 carries a 120-second timeout")
        elif any(proposal) or self.parameters.ttl_seconds is not None or self.risk != "none":
            raise ValueError("Runbook, target, parameters and risk require a proposal")
        if self.status == "diagnosed" and not self.evidence_ids:
            raise ValueError("Diagnosis requires evidence")
        return self


class RemediationParameters(Contract, frozen=True):
    source_ipv4: IPv4Address | None = None
    ttl_seconds: Annotated[int, Field(gt=0, le=120)] | None = None


class RemediationPlan(Contract, frozen=True):
    incident_id: Identifier
    runbook_id: RemediationID
    runbook_version: Version
    target: Node
    source_node: Node
    parameters: RemediationParameters = Field(default_factory=RemediationParameters)
    configuration_sha256: Digest | None = None
    evidence_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=16)]

    @property
    def digest(self):
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return sha256(canonical.encode()).hexdigest()


class AgentState(Contract):
    incident_id: Identifier
    phase: Phase = "collect"
    investigations: int = Field(default=0, ge=0, le=MAX_INVESTIGATIONS)
    invalid_retries: int = Field(default=0, ge=0, le=1)
    evidence_ids: tuple[Identifier, ...] = ()
    pending: ProbeRequest | None = None
    decision: Decision | None = None
    error: str | None = None

    def diagnosis(self):
        if self.phase not in {"collect", "investigate"}:
            raise ValueError("Diagnosis may follow collection or investigation")
        return self.model_copy(update={"phase": "diagnose", "pending": None})

    def investigation(self, tool):
        if self.phase != "diagnose":
            raise ValueError("Investigation may only follow diagnosis")
        if self.investigations >= MAX_INVESTIGATIONS:
            return self.need_human("investigation_limit")
        return self.model_copy(update={"phase": "investigate", "pending": tool,
                                       "investigations": self.investigations + 1})

    def finish(self, decision):
        if self.phase != "diagnose" or decision.status == "investigate":
            raise ValueError("Only a terminal decision can finish diagnosis")
        return self.model_copy(update={"phase": decision.status, "decision": decision})

    def need_human(self, reason):
        return self.model_copy(update={"phase": "need_human", "pending": None, "error": reason})
