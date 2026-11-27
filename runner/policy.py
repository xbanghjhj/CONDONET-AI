import json
import re
from ipaddress import IPv4Address, IPv4Network

from app.agent import grounded_findings
from app.eve_ingest import SIGNATURES
from app.retrieval import CATALOG
from app.schemas import RemediationParameters, RemediationPlan, known_probes
from lab.topology import HOST_BY_NAME, container_name
from runner.plans import DNS_FIXTURE, QUARANTINE_TTL_SECONDS, RUNBOOKS


class PolicyDenied(ValueError):
    pass


class RunnerPolicy:
    def __init__(self, lab):
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9-]{0,62}", lab):
            raise ValueError("Invalid Containerlab name")
        self.lab = lab
        self.versions = {row["id"]: row["version"] for row in json.loads(CATALOG.read_text())
                         if row["id"] in RUNBOOKS}

    def from_decision(self, incident, state, evidence):
        decision = state.decision if state else None
        if (state is None or state.incident_id != incident.id or state.phase != "propose"
                or decision is None or decision.status != "propose"
                or decision.runbook_id not in RUNBOOKS or decision.missing_evidence):
            raise PolicyDenied("No complete remediation proposal")
        observed = {item.id: item for item in evidence}
        if not set(decision.evidence_ids) <= observed.keys():
            raise PolicyDenied("Proposal references unavailable evidence")
        selected = [observed[key] for key in decision.evidence_ids]
        rule = RUNBOOKS[decision.runbook_id]
        findings = grounded_findings(incident, selected)
        if decision.hypothesis != rule.hypothesis or not findings.get(rule.hypothesis):
            raise PolicyDenied("Proposal does not match incident evidence")
        parameters = RemediationParameters()
        if decision.runbook_id == "RB03":
            addresses = {self.eve_source(incident, item) for item in selected}
            if len(addresses) != 1:
                raise PolicyDenied("Quarantine needs one confirmed alert source")
            parameters = RemediationParameters(source_ipv4=addresses.pop(),
                                              ttl_seconds=decision.parameters.ttl_seconds)
        plan = RemediationPlan(incident_id=incident.id, runbook_id=decision.runbook_id,
                               runbook_version=decision.runbook_version, target=decision.target,
                               source_node=incident.source_node, parameters=parameters,
                               configuration_sha256=rule.configuration_sha256,
                               evidence_ids=tuple(sorted(set(decision.evidence_ids))))
        self.validate(plan)
        return plan

    @staticmethod
    def eve_source(incident, item):
        details = item.evidence
        match = SIGNATURES.get(details.get("sid"))
        if (match is None or item.id not in incident.evidence_ids
                or (item.probe, item.status, item.source_node, item.reason) != ("eve", "alert", *match)
                or item.source_node != incident.source_node
                or item.target != f'{HOST_BY_NAME["svc"].address}:80'
                or details.get("label") != "lab_test" or details.get("dst_node") != "svc"
                or details.get("vlan") != HOST_BY_NAME[item.source_node].vlan):
            raise PolicyDenied("Alert was not ingested for this incident")
        try:
            return IPv4Address(details.get("src_ip"))
        except ValueError as error:
            raise PolicyDenied("Alert has no validated IPv4 source") from error

    def validate(self, plan):
        rule = RUNBOOKS[plan.runbook_id]
        if (self.versions.get(plan.runbook_id) != plan.runbook_version
                or plan.configuration_sha256 != rule.configuration_sha256):
            raise PolicyDenied("Runbook or standard configuration changed")
        parameters = plan.parameters
        if rule.process:
            if (plan.target != "svc" or f"{plan.source_node}-portal-http" not in known_probes()
                    or parameters != RemediationParameters()):
                raise PolicyDenied("Service target, source or parameters outside the allowlist")
            return "svc"
        if (plan.target != plan.source_node or plan.source_node not in {value[0] for value in SIGNATURES.values()}
                or parameters.ttl_seconds != QUARANTINE_TTL_SECONDS or parameters.source_ipv4 is None):
            raise PolicyDenied("Quarantine target or timeout outside the allowlist")
        host = HOST_BY_NAME[plan.source_node]
        address = parameters.source_ipv4
        network = IPv4Network(f"{host.address}/24", strict=False)
        if ((not host.dhcp and str(address) != host.address) or address not in network
                or str(address) == host.gateway or address in {network.network_address, network.broadcast_address}):
            raise PolicyDenied("Quarantine IP outside the source VLAN")
        return "gw"

    def argv(self, plan, operation, approval_id=None):
        node = self.validate(plan)
        rule = RUNBOOKS[plan.runbook_id]
        if rule.process:
            syntax = {
                "dns": ("dnsmasq", "--test", f"--conf-file={rule.mounted_path}"),
                "nginx": ("nginx", "-t", "-c", rule.mounted_path),
            }
            commands = {key: ("supervisorctl", key, rule.process)
                        for key in ("status", "start", "restart", "stop")}
            commands.update(config=("cat", rule.mounted_path), validate=syntax[rule.process])
            if rule.process == "dns":
                commands.update(fixture_present=("test", "-f", DNS_FIXTURE),
                                fixture_clear=("rm", "-f", DNS_FIXTURE),
                                fixture_restore=("touch", DNS_FIXTURE))
        else:
            element = ("ip", "condonet", "quarantine", "{", str(plan.parameters.source_ipv4))
            commands = {
                "list": ("nft", "-j", "list", "set", "ip", "condonet", "quarantine"),
                "counter": ("nft", "-j", "list", "counter", "ip", "condonet", "quarantine_forward"),
                "delete": ("nft", "destroy", "element", *element, "}"),
            }
            if operation == "add":
                if not approval_id or not re.fullmatch(r"[a-f0-9]{32}", approval_id):
                    raise PolicyDenied("Quarantine ownership needs a valid approval ID")
                commands["add"] = ("nft", "add", "element", *element, "timeout", f"{QUARANTINE_TTL_SECONDS}s",
                                   "comment", f'"condonet-{approval_id}"', "}")
        if operation not in commands:
            raise PolicyDenied("Operation outside the allowlist")
        return ("docker", "exec", "--env", "LC_ALL=C", container_name(self.lab, node),
                *commands[operation])
