import re
from dataclasses import dataclass
from pathlib import Path

from lab.topology import GATEWAYS, HOST_BY_NAME

MATRIX_PATH = Path(__file__).resolve().parents[1] / "tests" / "policy-cases.yaml"
TCP_CONNECT = """import socket, sys
try:
    with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2):
        pass
except TimeoutError:
    raise SystemExit(42)
"""


@dataclass(frozen=True)
class PolicyCase:
    id: str
    source: str
    destination: str
    protocol: str
    expect: str
    evidence: str
    port: int | None = None
    control: str | None = None

    @property
    def target(self):
        return self.destination, self.protocol, self.port


class CheckFailed(Exception):
    pass


def require(condition, message):
    if not condition:
        raise CheckFailed(message)


def load_cases():
    try:
        import yaml
    except ModuleNotFoundError as error:
        raise CheckFailed("Install PyYAML for the verifier (Ubuntu package python3-yaml)") from error

    try:
        matrix = yaml.safe_load(MATRIX_PATH.read_text(encoding="utf-8"))
        cases = {}
        sources = {*HOST_BY_NAME, "wan"}
        transports = {
            "echo-reply": {("icmp", None)},
            "ssh-banner": {("tcp", 22)},
            "dns-answer": {("udp", 53), ("tcp", 53)},
            "portal-body": {("tcp", 80)},
            "camera-body": {("tcp", 80)},
            "nat-source": {("tcp", 80)},
            "dhcp-lease": {("udp", 67)},
        }
        for row in matrix["cases"]:
            case = PolicyCase(**row)
            require(re.fullmatch(r"[a-z][a-z0-9-]+", case.id) and case.id not in cases,
                    f"Invalid or duplicate case ID: {case.id}")
            require(case.source in sources and case.destination in sources | GATEWAYS.keys(),
                    f"{case.id}: unknown source or destination")
            require(case.expect in {"allow", "canary", "deny"}, f"{case.id}: invalid expectation")
            if case.expect != "deny":
                require((case.protocol, case.port) in transports.get(case.evidence, ()),
                        f"{case.id}: protocol or port does not match the evidence")
            cases[case.id] = case
        require(cases, "Policy matrix is empty")
        for case in cases.values():
            if case.expect == "deny":
                control = cases.get(case.control)
                require(control and control.expect != "deny" and control.target == case.target
                        and control.source != case.source, f"{case.id}: invalid allow control")
                require(case.evidence in {"input-drop", "forward-drop"}
                        and case.protocol in {"tcp", "icmp"}, f"{case.id}: invalid deny probe")
    except (KeyError, OSError, TypeError, yaml.YAMLError) as error:
        raise CheckFailed(f"{MATRIX_PATH}: {error}") from error
    return cases


def ping_arguments(address, count=1):
    return ("ping", "-n", "-c", str(count), "-W", "1", "-w", "3", address)
