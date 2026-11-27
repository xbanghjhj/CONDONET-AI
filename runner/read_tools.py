import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from lab.policy import TCP_CONNECT, load_cases, ping_arguments
from lab.topology import (DNS_RECORDS, GATEWAYS, HOST_BY_NAME, HTTP_BODY_MARKERS, WAN_ADDRESS,
                          WAN_GATEWAY, container_name)

SOURCES = ("admin", "resident", "guest")
MONITORED_PROBES = (
    "admin-gateway-icmp", "resident-gateway-icmp", "guest-gateway-icmp",
    "admin-dns-udp", "resident-dns-udp", "guest-dns-udp",
    "admin-camera-http", "resident-portal-http", "guest-wan-http",
)
HTTP_SERVICES = {"portal-body": "portal", "camera-body": "camera", "nat-source": "wan"}


@dataclass(frozen=True)
class Probe:
    id: str
    source_node: str
    service: str
    tool: str
    address: str
    port: int | None = None
    transport: str | None = None

    @property
    def target(self):
        return f"{self.address}:{self.port}" if self.port else self.address

    @property
    def labels(self):
        return self.source_node, self.service, self.tool


@dataclass(frozen=True)
class ProbeResult:
    probe: Probe
    status: str
    reason: str
    evidence: dict
    measurements: dict
    timestamp: datetime
    id: str

    @classmethod
    def observed(cls, probe, status, reason, evidence=None, measurements=None):
        return cls(probe, status, reason, evidence or {}, measurements or {},
                   datetime.now(timezone.utc), uuid4().hex)

    def record(self):
        return {
            "id": self.id, "timestamp": self.timestamp.isoformat(timespec="milliseconds"),
            "source_node": self.probe.source_node, "service": self.probe.service,
            "probe": self.probe.tool, "probe_id": self.probe.id, "target": self.probe.target,
            "status": self.status, "reason": self.reason, "evidence": self.evidence,
            "measurements": self.measurements,
        }


def policy_probes():
    cases = load_cases()
    addresses = {**GATEWAYS, **{name: host.address for name, host in HOST_BY_NAME.items()},
                 "wan": WAN_ADDRESS}
    probes = {}
    for source in SOURCES:
        gateway = cases[f"{source}-gateway-icmp"]
        if gateway.expect == "allow":
            probes[gateway.id] = Probe(gateway.id, source, "gateway", "ping",
                                       addresses[gateway.destination])
        interface = f"{source}-interface"
        probes[interface] = Probe(interface, source, "interface", "interface", "eth1")
    for case in cases.values():
        if case.source not in SOURCES or case.expect == "deny":
            continue
        address = addresses[case.destination]
        if case.evidence == "dns-answer":
            probes[case.id] = Probe(case.id, case.source, "dns", "dns", address,
                                    case.port, case.protocol)
        if case.evidence in HTTP_SERVICES:
            service = HTTP_SERVICES[case.evidence]
            probes[case.id] = Probe(case.id, case.source, service, "http", address, case.port)
            if service == "portal":
                probe_id = f"{case.source}-portal-name-http"
                probes[probe_id] = Probe(probe_id, case.source, service, "http",
                                         "portal.condo.test", case.port)
            for tool in ("tcp", "route"):
                probe_id = f"{case.source}-{service}-{tool}"
                port = case.port if tool == "tcp" else None
                probes[probe_id] = Probe(probe_id, case.source, service, tool, address, port)
        if case.evidence == "ssh-banner":
            probe_id = f"{case.id}-tcp"
            probes[probe_id] = Probe(probe_id, case.source, case.destination, "tcp",
                                     address, case.port)
    return probes


class ReadOnlyRunner:
    def __init__(self, lab, timeout=6.0, execute=subprocess.run):
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9-]{0,62}", lab):
            raise ValueError("Invalid Containerlab name")
        if not 0 < timeout <= 8:
            raise ValueError("Runner timeout must be greater than 0 and at most 8 seconds")
        self.lab = lab
        self.timeout = timeout
        self.execute = execute
        self.probes = policy_probes()

    def command(self, probe):
        match probe.tool:
            case "ping":
                return (*ping_arguments(probe.address, count=2)[:-1], "-q", probe.address)
            case "dns":
                name = "internet.test" if probe.source_node == "guest" else "portal.condo.test"
                transport = "+tcp" if probe.transport == "tcp" else "+notcp"
                return ("dig", f"@{probe.address}", "-p", str(probe.port), transport,
                        "+time=2", "+tries=1", "+noall", "+answer", "+stats", name, "A")
            case "tcp":
                return ("python3", "-c", TCP_CONNECT, probe.address, str(probe.port))
            case "http":
                path = "/source" if probe.service == "wan" else "/"
                url = f"http://{probe.target}{path}"
                return ("curl", "--noproxy", "*", "--silent", "--show-error",
                        "--connect-timeout", "2", "--max-time", "4", "--max-filesize", "8192",
                        "--write-out", "\n%{http_code} %{time_total}", url)
            case "interface":
                return ("ip", "-j", "address", "show", "dev", probe.address)
            case "route":
                return ("ip", "-j", "-4", "route", "get", probe.address)
        raise ValueError(f"Unsupported probe tool: {probe.tool}")

    def run(self, probe_id):
        if probe_id not in self.probes:
            raise ValueError(f"Probe outside the allowlist: {probe_id}")
        probe = self.probes[probe_id]
        container = container_name(self.lab, probe.source_node)
        evidence = {"container": container}
        argv = ("docker", "exec", "--env", "LC_ALL=C", container, *self.command(probe))
        try:
            result = self.execute(argv, timeout=self.timeout, capture_output=True, text=True,
                                  errors="replace")
        except subprocess.TimeoutExpired:
            return ProbeResult.observed(probe, "missing", "runner_timeout", evidence)
        except OSError:
            return ProbeResult.observed(probe, "missing", "runner_error", evidence)
        evidence["exit_code"] = result.returncode
        try:
            match probe.tool:
                case "ping":
                    status, reason, details, measurements = self.ping(result)
                case "dns":
                    status, reason, details, measurements = self.dns(probe, result)
                case "http":
                    status, reason, details, measurements = self.http(probe, result)
                case "tcp":
                    status, reason, details, measurements = self.tcp(result)
                case "interface" | "route":
                    status, reason, details, measurements = self.network(probe, result)
        except (ValueError, KeyError, IndexError, TypeError):
            return ProbeResult.observed(probe, "missing", "invalid_probe_output", evidence)
        return ProbeResult.observed(probe, status, reason, {**evidence, **details}, measurements)

    @staticmethod
    def ping(result):
        if result.returncode == 2 and "Network is unreachable" in result.stderr:
            return "failed", "icmp_unreachable", {}, {}
        loss = re.search(r"([\d.]+)% packet loss", result.stdout)
        if result.returncode not in (0, 1) or not loss:
            return "missing", "runner_error", {}, {}
        measurements = {"packet_loss_ratio": float(loss[1]) / 100}
        rtt = re.search(r" = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms", result.stdout)
        if rtt:
            measurements["rtt_seconds"] = float(rtt[1]) / 1000
        if measurements["packet_loss_ratio"] == 1:
            return "failed", "icmp_unreachable", {}, measurements
        return "healthy", "echo_reply", {}, measurements

    @staticmethod
    def dns(probe, result):
        name = "internet.test" if probe.source_node == "guest" else "portal.condo.test"
        details = {"query": name, "transport": probe.transport}
        if result.returncode == 9 and "no servers could be reached" in result.stdout:
            reason = "probe_timeout" if "timed out" in result.stdout else "dns_unreachable"
            return "failed", reason, details, {"dns_success": 0}
        latency = re.search(r"Query time: (\d+) msec", result.stdout)
        if result.returncode != 0 or not latency:
            return "missing", "runner_error", details, {}
        answers = {parts[-1] for parts in map(str.split, result.stdout.splitlines())
                   if len(parts) == 5 and parts[0] == f"{name}." and parts[2:4] == ["IN", "A"]}
        details["answers"] = sorted(answers)
        success = answers == {DNS_RECORDS[name]}
        measurements = {"dns_success": int(success), "dns_latency_seconds": int(latency[1]) / 1000}
        return ("healthy" if success else "failed",
                "dns_answer" if success else "dns_answer_mismatch", details, measurements)

    @staticmethod
    def http(probe, result):
        network_failures = {7: "connection_failure", 18: "http_transport", 28: "probe_timeout",
                            52: "http_transport", 56: "http_transport", 63: "body_too_large"}
        if result.returncode in network_failures:
            return "failed", network_failures[result.returncode], {}, {}
        if result.returncode != 0:
            return "missing", "runner_error", {}, {}
        body, summary = result.stdout.rsplit("\n", 1)
        status, latency = summary.split()
        if probe.service == "wan":
            try:
                body_matches = json.loads(body) == {"source": WAN_GATEWAY}
            except json.JSONDecodeError:
                body_matches = False
        else:
            body_matches = HTTP_BODY_MARKERS[probe.service] in body
        measurements = {"http_status": int(status), "http_body_match": int(body_matches),
                        "http_latency_seconds": float(latency)}
        if status != "200":
            return "failed", "http_status", {}, measurements
        if not body_matches:
            return "failed", "http_body_mismatch", {}, measurements
        return "healthy", "http_response", {}, measurements

    @staticmethod
    def tcp(result):
        if result.returncode == 0:
            return "healthy", "tcp_connected", {}, {}
        if result.returncode == 42:
            return "failed", "probe_timeout", {}, {}
        if any(message in result.stderr for message in ("ConnectionRefusedError", "No route to host",
                                                        "Network is unreachable")):
            return "failed", "connection_failure", {}, {}
        return "missing", "runner_error", {}, {}

    @staticmethod
    def network(probe, result):
        if (probe.tool == "route" and result.returncode == 2
                and "Network is unreachable" in result.stderr):
            return "failed", "route_unreachable", {}, {}
        if result.returncode != 0:
            return "missing", "runner_error", {}, {}
        row = json.loads(result.stdout)[0]
        if probe.tool == "interface":
            addresses = [f"{entry['local']}/{entry['prefixlen']}" for entry in row["addr_info"]
                         if entry["family"] == "inet"]
            details = {"interface": row["ifname"], "addresses": addresses,
                       "up": "UP" in row.get("flags", ()), "operstate": row.get("operstate")}
        else:
            details = {"interface": row["dev"], "source_address": row["prefsrc"],
                       "gateway": row.get("gateway")}
        return "healthy", "network_state", details, {}


def main():
    parser = argparse.ArgumentParser(description="Run one allowlisted read-only CondoNet probe.")
    parser.add_argument("--lab", required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--list", action="store_true")
    selection.add_argument("--probe")
    args = parser.parse_args()
    try:
        runner = ReadOnlyRunner(args.lab)
        if args.list:
            print("\n".join(sorted(runner.probes)))
            return 0
        result = runner.run(args.probe)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(result.record()))
    return {"healthy": 0, "failed": 1, "missing": 2}[result.status]


if __name__ == "__main__":
    raise SystemExit(main())
