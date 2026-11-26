import argparse
import json
import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Host:
    name: str
    vlan: int
    port: str
    dhcp: bool = False

    @property
    def address(self):
        return f"10.60.{self.vlan}.10"

    @property
    def gateway(self):
        return f"10.60.{self.vlan}.1"


HOSTS = (
    Host("admin", 10, "eth2"),
    Host("resident", 20, "eth3", dhcp=True),
    Host("guest", 30, "eth4", dhcp=True),
    Host("camera", 40, "eth5"),
    Host("svc", 50, "eth6"),
)
HOST_BY_NAME = {host.name: host for host in HOSTS}
GATEWAYS = {f"gw-{host.name}": host.gateway for host in HOSTS}
WAN_ADDRESS = "10.60.254.2"
WAN_GATEWAY = "10.60.254.1"
DNS_ADDRESS = HOST_BY_NAME["svc"].address
DNS_RECORDS = {"portal.condo.test": DNS_ADDRESS, "internet.test": WAN_ADDRESS}
HTTP_BODY_MARKERS = {"portal": "CondoNet Portal", "camera": "CondoNet Camera"}
MATRIX_PATH = Path(__file__).resolve().parents[1] / "tests" / "policy-cases.yaml"
DHCP_LOG = "/var/log/condonet-dhcp.log"
SSH_BANNER = """import socket, sys
with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3) as conn:
    with conn.makefile("rb") as stream:
        print(stream.readline(256).decode().strip())
"""
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


def container_name(lab, node):
    return f"clab-{lab}-{node}"


def ping_arguments(address, count=1):
    return ("ping", "-n", "-c", str(count), "-W", "1", "-w", "3", address)


class LabVerifier:
    def __init__(self, lab, output, cases):
        self.lab = lab
        self.output = output
        self.cases = cases
        self.addresses = {**GATEWAYS, "wan": WAN_ADDRESS}
        self.checks = []
        self.log = None

    def command_result(self, *args, timeout=15):
        self.log.write(f"$ {shlex.join(args)}\n")
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        self.log.write(result.stdout)
        self.log.write(result.stderr)
        self.log.write(f"exit={result.returncode}\n")
        return result

    def command(self, *args, timeout=15):
        result = self.command_result(*args, timeout=timeout)
        require(result.returncode == 0, f"Exit {result.returncode}: {shlex.join(args)}")
        return result.stdout

    def node_name(self, node):
        return container_name(self.lab, node)

    def node_args(self, node, *args):
        return ("docker", "exec", self.node_name(node), *args)

    def node(self, node, *args, timeout=15):
        return self.command(*self.node_args(node, *args), timeout=timeout)

    def node_json(self, node, *args):
        return json.loads(self.node(node, *args))

    def check(self, name, action, blocked_by=None):
        log_path = self.output / f"{name}.log"
        status = "NOT RUN"
        if action is not None:
            with log_path.open("w", encoding="utf-8") as self.log:
                try:
                    action()
                except (CheckFailed, ValueError, KeyError, IndexError, TypeError, OSError,
                        subprocess.TimeoutExpired) as error:
                    status = "FAIL"
                    self.log.write(f"{error}\n")
                else:
                    status = "PASS"
        self.checks.append({
            "name": name,
            "status": status,
            "log": str(log_path) if action is not None else None,
            "reason": f"{blocked_by} did not pass" if blocked_by else None,
        })
        print(f"{name}: {status}", flush=True)
        return status == "PASS"

    def topology(self):
        interfaces = {host.name: {"lo", "eth1"} for host in HOSTS}
        interfaces.update({
            "sw": {"lo", "br0", *(f"eth{i}" for i in range(1, 7))},
            "gw": {"lo", "eth1", "eth2", *(f"eth1.{host.vlan}" for host in HOSTS)},
            "wan": {"lo", "eth1"},
        })

        running = self.command("docker", "ps", "--filter", f"label=containerlab={self.lab}",
                               "--format", "{{.Names}}")
        require(set(running.splitlines()) == {self.node_name(node) for node in interfaces},
                "Expected exactly eight running nodes with the lab label")
        inventory = {}
        for node, expected in interfaces.items():
            mode = self.command("docker", "inspect", "--format", "{{.HostConfig.NetworkMode}}",
                                self.node_name(node))
            require(mode.strip() == "none", f"{node}: unexpected network mode")
            links = self.node_json(node, "ip", "-j", "link", "show")
            require({link["ifname"] for link in links} == expected, f"{node}: unexpected interfaces")
            inventory[node] = {link["ifname"]: link for link in links}
            ipv6 = self.node(node, "sysctl", "-n", "net.ipv6.conf.all.disable_ipv6",
                             "net.ipv6.conf.default.disable_ipv6")
            require(ipv6.split() == ["1", "1"], f"{node}: IPv6 is enabled")
            ipv6_links = self.node_json(node, "ip", "-j", "-6", "address", "show")
            require(not any(link.get("addr_info") for link in ipv6_links),
                    f"{node}: unexpected IPv6 addresses")

        peers = [("sw", "eth1", "gw", "eth1"), ("gw", "eth2", "wan", "eth1")]
        peers.extend(("sw", host.port, host.name, "eth1") for host in HOSTS)
        for left, left_port, right, right_port in peers:
            first = inventory[left][left_port]
            second = inventory[right][right_port]
            require(first.get("link_index") == second["ifindex"] and
                    second.get("link_index") == first["ifindex"],
                    f"Unexpected peers for {left}:{left_port} and {right}:{right_port}")

    def vlan(self):
        bridge = self.node_json("sw", "ip", "-j", "-d", "link", "show", "dev", "br0")[0]
        info = bridge["linkinfo"]["info_data"]
        require(info["vlan_filtering"] == 1, "br0: filtering disabled")
        require(info["vlan_default_pvid"] == 0, "br0: default VLAN is enabled")
        rows = self.node_json("sw", "bridge", "-j", "vlan", "show")
        vlans = {row["ifname"]: {entry["vlan"]: set(entry.get("flags", [])) for entry in row["vlans"]}
                 for row in rows}
        require(all(1 not in entries for entries in vlans.values()), "Unexpected membership in VLAN 1")
        for host in HOSTS:
            require(vlans[host.port] == {host.vlan: {"PVID", "Egress Untagged"}},
                    f"{host.port}: expected one untagged access VLAN {host.vlan}")
        require(vlans["eth1"] == {host.vlan: set() for host in HOSTS}, "eth1: wrong tagged VLANs")

    def ipv4(self, node, interface):
        links = self.node_json(node, "ip", "-j", "-4", "addr", "show", "dev", interface)
        return {(entry["local"], entry["prefixlen"])
                for link in links for entry in link.get("addr_info", [])}

    def default_route(self, node, gateway, interface):
        routes = self.node_json(node, "ip", "-j", "-4", "route", "show", "default")
        require(len(routes) == 1 and routes[0].get("gateway") == gateway and
                routes[0].get("dev") == interface, f"{node}: unexpected default route")

    def lease(self, host):
        self.node(host.name, "timeout", "45", "sh", "-c",
                  'until ip -4 -o addr show dev eth1 scope global | grep -q inet && '
                  'grep -qx "nameserver 10.60.50.10" /etc/resolv.conf; do sleep 1; done',
                  timeout=48)
        addresses = self.ipv4(host.name, "eth1")
        require(len(addresses) == 1, f"{host.name}: expected a single lease")
        address, prefix = next(iter(addresses))
        pool = {f"10.60.{host.vlan}.{last}" for last in range(100, 150)}
        require(address in pool and prefix == 24, f"{host.name}: invalid address or lease prefix")
        link = self.node_json(host.name, "ip", "-j", "link", "show", "dev", "eth1")[0]
        entries = self.node("gw", "cat", "/var/lib/misc/condonet-dhcp.leases").splitlines()
        require(any(len(entry) >= 3 and entry[1:3] == [link["address"], address] and
                    int(entry[0]) > time.time() for entry in map(str.split, entries)),
                f"{host.name}: active lease for {link['address']} missing on gateway")
        self.default_route(host.name, host.gateway, "eth1")
        resolver = self.node(host.name, "cat", "/etc/resolv.conf")
        servers = [line.split()[1:] for line in resolver.splitlines()
                   if line.split()[:1] == ["nameserver"]]
        require(servers == [[DNS_ADDRESS]], f"{host.name}: wrong resolvers")
        self.addresses[host.name] = address
        return link["address"]

    def routing(self):
        require(not self.ipv4("gw", "eth1"), "gw: untagged address on trunk")
        require(self.node("gw", "sysctl", "-n", "net.ipv4.ip_forward").strip() == "1",
                "gw: IPv4 forwarding disabled")
        for host in HOSTS:
            device = f"eth1.{host.vlan}"
            subinterface = self.node_json("gw", "ip", "-j", "-d", "link", "show", "dev", device)[0]
            vlan = subinterface["linkinfo"]
            require(subinterface.get("link") == "eth1" and vlan["info_kind"] == "vlan" and
                    vlan["info_data"]["id"] == host.vlan and
                    vlan["info_data"]["protocol"] == "802.1Q", f"gw: incorrect {device}")
            require(self.ipv4("gw", device) == {(host.gateway, 24)}, f"gw: wrong IP on {device}")
            if host.dhcp:
                self.lease(host)
            else:
                require(self.ipv4(host.name, "eth1") == {(host.address, 24)}, f"{host.name}: wrong IP")
                self.default_route(host.name, host.gateway, "eth1")
                self.addresses[host.name] = host.address
            route = self.node_json("gw", "ip", "-j", "route", "get", self.addresses[host.name])[0]
            require(route.get("dev") == device and "gateway" not in route,
                    f"gw: {host.name} is not directly connected via {device}")

        require(self.ipv4("gw", "eth2") == {(WAN_GATEWAY, 30)}, "gw: wrong WAN IP")
        require(self.ipv4("wan", "eth1") == {(WAN_ADDRESS, 30)}, "wan: wrong transit IP")
        self.default_route("gw", WAN_ADDRESS, "eth2")
        self.route_from("wan", "resident")

    def route_from(self, source, destination):
        target = self.addresses[destination]
        gateway = WAN_GATEWAY if source == "wan" else HOST_BY_NAME[source].gateway
        next_hop = None if target == gateway else gateway
        route = self.node_json(source, "ip", "-j", "route", "get", target)[0]
        require(route.get("dev") == "eth1" and route.get("gateway") == next_hop and
                route.get("prefsrc") == self.addresses[source],
                f"{source}: wrong route or source IP for {destination}")
        return target

    def nft_items(self, *args, kind):
        rows = self.node_json("gw", "nft", "-j", "list", *args)["nftables"]
        return [row[kind] for row in rows if kind in row]

    def counter(self, name):
        return self.nft_items("counter", "ip", "condonet", name, kind="counter")[0]["packets"]

    def increased(self, name, before):
        after = self.counter(name)
        self.log.write(f"{name}: {before} -> {after}\n")
        require(after > before, f"{name} did not increase")

    def quarantine_empty(self):
        state = self.nft_items("set", "ip", "condonet", "quarantine", kind="set")[0]
        require(state["type"] == "ipv4_addr" and state["timeout"] == 120 and
                "timeout" in state["flags"] and not state.get("elem"),
                "Expected an empty IPv4 quarantine set with a 120-second timeout")

    def firewall(self):
        chains = {chain["name"]: chain for chain in
                  self.nft_items("table", "ip", "condonet", kind="chain")}
        for name, chain_type, priority, policy in (("input", "filter", 0, "drop"),
                                                    ("forward", "filter", 0, "drop"),
                                                    ("postrouting", "nat", 100, "accept")):
            chain = chains[name]
            require((chain["hook"], chain["type"], chain["prio"], chain["policy"]) ==
                    (name, chain_type, priority, policy), f"Unexpected {name} hook or policy")
        self.quarantine_empty()

    def http(self, source, url):
        output = self.node(source, "curl", "--noproxy", "*", "-fsS",
                           "--connect-timeout", "2", "--max-time", "4",
                           "--write-out", "\n%{http_code}", url)
        body, status = output.rsplit("\n", 1)
        require(status == "200", f"{source}: unexpected HTTP {status} for {url}")
        return body

    def services(self):
        expected = {"gw": {"dhcp", "ssh"}, "svc": {"dns", "nginx", "ssh"},
                    "camera": {"nginx"}, "wan": {"wan-http"},
                    "resident": {"dhcp-client"}, "guest": {"dhcp-client"}}
        for node, programs in expected.items():
            status = self.node(node, "supervisorctl", "status")
            running = {parts[0] for parts in map(str.split, status.splitlines())
                       if parts[1:2] == ["RUNNING"]}
            require(running == programs, f"{node}: expected running programs {sorted(programs)}")
        before = self.counter("forward_established")
        for source in ("resident", "guest"):
            for name, address in DNS_RECORDS.items():
                output = self.node(source, "getent", "ahostsv4", name)
                require({row.split()[0] for row in output.splitlines()} == {address},
                        f"{source}: wrong system resolver answer for {name}")
        require(HTTP_BODY_MARKERS["portal"] in self.http("resident", "http://portal.condo.test/"),
                "Portal content is missing")
        self.increased("forward_established", before)

    def fresh_dhcp(self, case):
        host = HOST_BY_NAME[case.source]
        require(host.dhcp and case.target == (f"gw-{host.name}", "udp", 67),
                f"{case.id}: invalid DHCP probe")
        before = self.counter("dhcp_allow")
        offset = len(self.node("gw", "cat", DHCP_LOG).splitlines())
        self.node(host.name, "supervisorctl", "stop", "dhcp-client")
        try:
            self.node(host.name, "env", "interface=eth1", "/condonet/dhcp-lease.sh", "deconfig")
            require(not self.ipv4(host.name, "eth1"), f"{host.name}: client still has an address")
            require(not self.node_json(host.name, "ip", "-j", "-4", "route", "show", "default"),
                    f"{host.name}: stale default route")
        finally:
            self.node(host.name, "supervisorctl", "start", "dhcp-client")
        mac = self.lease(host)
        self.increased("dhcp_allow", before)

        transactions = {}
        pattern = re.compile(rf"(\d+) DHCP(DISCOVER|OFFER|REQUEST|ACK)\(eth1\.{host.vlan}\) (.*)")
        for line in self.node("gw", "cat", DHCP_LOG).splitlines()[offset:]:
            match = pattern.search(line)
            if match and mac in match[3].split():
                transaction, phase, fields = match.groups()
                if phase == "DISCOVER" or self.addresses[host.name] in fields.split():
                    transactions.setdefault(transaction, []).append(phase)
        phases = ["DISCOVER", "OFFER", "REQUEST", "ACK"]
        require(any(list(dict.fromkeys(observed)) == phases for observed in transactions.values()),
                f"{case.id}: complete DORA transaction missing")

    def ping_args(self, address):
        return ping_arguments(address)

    def allow(self, case):
        if case.evidence == "dhcp-lease":
            self.fresh_dhcp(case)
            return

        source = case.source
        address = self.route_from(source, case.destination)
        if case.evidence == "echo-reply":
            counter = "gateway_icmp_allow" if case.destination in GATEWAYS else "lab_icmp_allow"
            before = self.counter(counter)
            self.node(source, *self.ping_args(address))
        elif case.evidence == "ssh-banner":
            counter = "gateway_ssh_allow" if case.destination in GATEWAYS else "svc_ssh_allow"
            before = self.counter(counter)
            banner = self.node(source, "python3", "-c", SSH_BANNER, address, str(case.port))
            require(banner.startswith("SSH-2.0-"), f"{case.id}: invalid SSH banner")
        elif case.evidence == "dns-answer":
            counter = "dns_allow"
            before = self.counter(counter)
            transport = "+tcp" if case.protocol == "tcp" else "+notcp"
            for name, expected in DNS_RECORDS.items():
                answer = self.node(source, "dig", f"@{address}", "-p", str(case.port), transport,
                                   "+time=2", "+tries=1", "+short", name, "A")
                require(answer.strip() == expected, f"{case.id}: unexpected DNS answer for {name}")
        elif case.evidence == "nat-source":
            counter = "wan_http_allow"
            before = self.counter(counter)
            before_nat = self.counter("wan_nat")
            response = json.loads(self.http(source, f"http://{address}:{case.port}/source"))
            require(response.get("source") == WAN_GATEWAY, f"{case.id}: wrong NAT source")
            self.increased("wan_nat", before_nat)
        else:
            counter, marker = {"portal-body": ("portal_allow", HTTP_BODY_MARKERS["portal"]),
                               "camera-body": ("camera_allow", HTTP_BODY_MARKERS["camera"])}[case.evidence]
            before = self.counter(counter)
            require(marker in self.http(source, f"http://{address}:{case.port}/"),
                    f"{case.id}: wrong HTTP body")
        self.increased(counter, before)

    def deny(self, case):
        self.log.write(f"Positive control: {case.control}\n")
        self.allow(self.cases[case.control])
        address = self.route_from(case.source, case.destination)
        counter = case.evidence.replace("-", "_")
        before = self.counter(counter)
        if case.protocol == "tcp":
            probe = ("python3", "-c", TCP_CONNECT, address, str(case.port))
            expected_status = 42
        else:
            probe = self.ping_args(address)
            expected_status = 1
        result = self.command_result(*self.node_args(case.source, *probe))
        require(result.returncode == expected_status,
                f"{case.id}: unexpected probe exit {result.returncode}, expected {expected_status}")
        self.increased(counter, before)

    def run(self):
        blocked_by = None
        checks = (("topology", self.topology), ("vlan", self.vlan), ("routing", self.routing),
                  ("firewall", self.firewall), ("services", self.services))
        for name, action in checks:
            if blocked_by:
                self.check(name, None, blocked_by)
            elif not self.check(name, action):
                blocked_by = name

        for case in self.cases.values():
            action = self.deny if case.expect == "deny" else self.allow
            self.check(case.id, None if blocked_by else lambda: action(case), blocked_by)
        self.check("quarantine-after-matrix", None if blocked_by else self.quarantine_empty, blocked_by)

        results = {check["name"]: check["status"] for check in self.checks}
        matrix = {status: sum(results[case_id] == status for case_id in self.cases)
                  for status in ("PASS", "FAIL", "NOT RUN")}
        summary = self.output / "summary.json"
        summary.write_text(json.dumps({"lab": self.lab, "matrix": matrix, "checks": self.checks},
                                      indent=2) + "\n", encoding="utf-8")
        print(f"Matrix: {matrix}\n{summary}")
        return all(status == "PASS" for status in results.values())


def main():
    parser = argparse.ArgumentParser(description="Verify the running CondoNet DHCP, DNS and firewall lab.")
    parser.add_argument("--lab", default="condonet")
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        cases = load_cases()
        output = args.out_dir.resolve()
        output.mkdir(parents=True, exist_ok=False)
    except (CheckFailed, OSError) as error:
        parser.error(str(error))
    return 0 if LabVerifier(args.lab, output, cases).run() else 1


if __name__ == "__main__":
    raise SystemExit(main())
