import argparse
import json
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Host:
    name: str
    vlan: int
    port: str

    @property
    def address(self):
        return f"10.60.{self.vlan}.10"

    @property
    def gateway(self):
        return f"10.60.{self.vlan}.1"


HOSTS = (
    Host("admin", 10, "eth2"),
    Host("resident", 20, "eth3"),
    Host("guest", 30, "eth4"),
    Host("camera", 40, "eth5"),
    Host("svc", 50, "eth6"),
)
WAN_URL = "http://10.60.254.2:8080/source"


class CheckFailed(Exception):
    pass


def require(condition, message):
    if not condition:
        raise CheckFailed(message)


class LabVerifier:
    def __init__(self, lab, output):
        self.lab = lab
        self.output = output
        self.checks = []
        self.log = None

    def command(self, *args):
        self.log.write(f"$ {shlex.join(args)}\n")
        result = subprocess.run(args, capture_output=True, text=True, timeout=15)
        self.log.write(result.stdout)
        self.log.write(result.stderr)
        require(result.returncode == 0, f"Exit {result.returncode}: {shlex.join(args)}")
        return result.stdout

    def node_name(self, node):
        return f"clab-{self.lab}-{node}"

    def node(self, node, *args):
        return self.command("docker", "exec", self.node_name(node), *args)

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
        require(bridge["linkinfo"]["info_data"]["vlan_filtering"] == 1, "br0: filtering disabled")
        rows = self.node_json("sw", "bridge", "-j", "vlan", "show")
        vlans = {row["ifname"]: {entry["vlan"]: set(entry.get("flags", [])) for entry in row["vlans"]}
                 for row in rows}
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

    def ping(self, node, target):
        self.node(node, "ping", "-n", "-c", "2", "-W", "1", "-w", "4", target)

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
            route = self.node_json("gw", "ip", "-j", "route", "get", host.address)[0]
            require(route.get("dev") == device and "gateway" not in route,
                    f"gw: {host.name} is not directly connected via {device}")
            require(self.ipv4(host.name, "eth1") == {(host.address, 24)}, f"{host.name}: wrong IP")
            self.default_route(host.name, host.gateway, "eth1")
            self.ping(host.name, host.gateway)

        for source, destination in ((HOSTS[1], HOSTS[-1]), (HOSTS[-1], HOSTS[1])):
            route = self.node_json(source.name, "ip", "-j", "route", "get", destination.address)[0]
            require(route.get("gateway") == source.gateway and route.get("dev") == "eth1",
                    f"{source.name}: wrong route to {destination.name}")
            self.ping(source.name, destination.address)

    def nat_counter(self):
        chain = self.node_json("gw", "nft", "-j", "list", "chain", "ip", "condonet", "postrouting")
        for item in chain["nftables"]:
            expressions = item.get("rule", {}).get("expr", [])
            if any("masquerade" in expr for expr in expressions):
                counter = next((expr["counter"] for expr in expressions if "counter" in expr), None)
                require(counter is not None, "Missing masquerade counter")
                return counter["packets"]
        raise CheckFailed("Missing masquerade rule")

    def wan(self):
        require(self.ipv4("gw", "eth2") == {("10.60.254.1", 30)}, "gw: wrong WAN IP")
        require(self.ipv4("wan", "eth1") == {("10.60.254.2", 30)}, "wan: wrong transit IP")
        self.default_route("gw", "10.60.254.2", "eth2")
        route = self.node_json("gw", "ip", "-j", "route", "get", "198.51.100.2")[0]
        require(route.get("gateway") == "10.60.254.2" and route.get("dev") == "eth2",
                "gw: wrong default next hop")

        for host in HOSTS:
            before = self.nat_counter()
            response = self.node_json(host.name, "curl", "-fsS", "--max-time", "5", WAN_URL)
            require(response.get("source") == "10.60.254.1", f"{host.name}: wrong NAT source")
            require(self.nat_counter() > before, f"{host.name}: NAT counter did not increase")

    def run(self):
        blocked_by = None
        checks = (("topology", self.topology), ("vlan", self.vlan),
                  ("routing", self.routing), ("wan-nat", self.wan))
        for name, action in checks:
            if blocked_by is not None:
                self.check(name, None, blocked_by)
            elif not self.check(name, action):
                blocked_by = name
        summary = self.output / "summary.json"
        summary.write_text(json.dumps({"lab": self.lab, "checks": self.checks}, indent=2) + "\n",
                           encoding="utf-8")
        print(summary)
        return blocked_by is None


def main():
    parser = argparse.ArgumentParser(description="Verify the running CondoNet Day 2 baseline.")
    parser.add_argument("--lab", default="condonet")
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.out_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    return 0 if LabVerifier(args.lab, output).run() else 1


if __name__ == "__main__":
    raise SystemExit(main())
