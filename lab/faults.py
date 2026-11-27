import json
import re
from contextlib import ExitStack, contextmanager
from dataclasses import asdict
from time import sleep
from uuid import uuid4

from app.incident_store import Evidence
from lab.policy import require
from lab.topology import HOST_BY_NAME
from runner.plans import DNS_FIXTURE
from runner.read_tools import ReadOnlyRunner


class LabFaults:
    def __init__(self, verifier, eve):
        require(re.fullmatch(r"condonet-day(?:09|10)(?:-[a-z0-9-]+)?", verifier.lab),
                "Use a dedicated CondoNet Day 9 or Day 10 lab")
        self.lab = verifier
        self.probes = ReadOnlyRunner(verifier.lab)
        self.eve = eve

    def service(self, node, operation, name):
        return self.lab.node(node, "supervisorctl", operation, name)

    def probe(self, key, expected):
        probe = self.probes.probes[key]
        result = self.probes.run(key).record()
        self.lab.log.write(json.dumps(result, ensure_ascii=False) + "\n")
        require((result["probe_id"], result["source_node"], result["target"], result["status"],
                 result["evidence"].get("container")) == (
                     key, probe.source_node, probe.target, expected, self.lab.node_name(probe.source_node)),
                f"{key}: expected {expected}, got {result['status']} ({result['reason']})")
        return result

    def restore_service(self, node, name):
        live = self.lab.command_result(*self.lab.node_args(node, "supervisorctl", "status", name))
        if live.returncode == 3 and live.stdout.split()[1:2] == ["STOPPED"]:
            self.service(node, "start", name)
        else:
            require(live.returncode == 0 and live.stdout.split()[1:2] == ["RUNNING"], f"{name} cannot reset")

    def restore_dns(self):
        flag = self.lab.command_result(*self.lab.node_args("svc", "test", "-f", DNS_FIXTURE))
        require(flag.returncode in (0, 1), "Could not check DNS fixture marker")
        self.lab.node("svc", "rm", "-f", DNS_FIXTURE, "/run/condonet-dns-active.conf")
        if flag.returncode == 0:
            self.service("svc", "restart", "dns")

    def vlans(self, port):
        rows = self.lab.node_json("sw", "bridge", "-j", "vlan", "show", "dev", port)
        return {entry["vlan"]: entry.get("flags", []) for row in rows for entry in row["vlans"]}

    def restore_vlan(self):
        if 20 not in self.vlans("eth1"):
            self.lab.node("sw", "bridge", "vlan", "add", "dev", "eth1", "vid", "20")

    def qdiscs(self):
        return self.lab.node_json("resident", "tc", "-j", "qdisc", "show", "dev", "eth1")

    def restore_qdisc(self):
        if any(row["kind"] == "netem" and row["handle"] == "909:" for row in self.qdiscs()):
            self.lab.node("resident", "tc", "qdisc", "del", "dev", "eth1", "root", "handle", "909:")

    @contextmanager
    def inject(self, case, mark):
        with ExitStack() as reset:
            node = self.lab.node
            if case == "01":
                reset.callback(self.restore_dns)
                mark()
                node("svc", "touch", DNS_FIXTURE)
                self.service("svc", "restart", "dns")
            elif case == "02":
                reset.callback(self.restore_service, "svc", "nginx")
                mark()
                self.service("svc", "stop", "nginx")
            elif case == "03":
                require(self.vlans("eth1").get(20) == [], "VLAN 20 is not tagged in baseline")
                reset.callback(self.restore_vlan)
                mark()
                node("sw", "bridge", "vlan", "del", "dev", "eth1", "vid", "20")
            elif case == "04":
                reset.callback(self.restore_service, "guest", "dhcp-client")
                reset.callback(self.restore_service, "gw", "dhcp")
                mark()
                self.service("gw", "stop", "dhcp")
                self.service("guest", "stop", "dhcp-client")
                node("guest", "env", "interface=eth1", "/condonet/dhcp-lease.sh", "deconfig")
                self.service("guest", "start", "dhcp-client")
            elif case == "05":
                require(all(row["kind"] == "noqueue" for row in self.qdiscs()), "Custom qdisc already present")
                reset.callback(self.restore_qdisc)
                mark()
                node("resident", "tc", "qdisc", "add", "dev", "eth1", "root", "handle", "909:",
                     "netem", "loss", "20%")
            elif case == "06":
                require(self.eve is not None and self.eve.is_file(), "Live EVE file required for RB03")
                offset = self.eve.stat().st_size
                mark()
                status = node("resident", "curl", "--noproxy", "*", "--silent", "--show-error",
                              "--connect-timeout", "2", "--max-time", "4", "--output", "/dev/null",
                              "--write-out", "%{http_code}", f"http://{HOST_BY_NAME['svc'].address}/lab-alert")
                require(status == "404", "The harmless IDS route did not return the expected HTTP status")
                yield offset
                return
            yield None

    def evidence(self, source, service, probe, target, status, reason, details, sample, measurements=None):
        return Evidence(uuid4().hex, sample["timestamp"], source, service, probe, target, status,
                        reason, details, measurements or {})

    def network_evidence(self, case):
        if case == "03":
            return [self.vlan_evidence()]
        if case == "04":
            return [self.dhcp_evidence()]
        if case == "05":
            return [self.loss_evidence()]
        return [self.policy_evidence(key) for key in ("guest-portal-deny", "guest-camera-deny")]

    def vlan_evidence(self):
        resident = self.probe("resident-gateway-icmp", "failed")
        interface = self.probe("resident-interface", "healthy")
        guest = self.probe("guest-gateway-icmp", "healthy")
        fdb = self.lab.node_json("sw", "bridge", "-j", "fdb", "show", "dev", "eth3")
        link, = self.lab.node_json("resident", "ip", "-j", "link", "show", "dev", "eth1")
        details = {"trunk_vlans": sorted(self.vlans("eth1")), "resident_access_pvid": self.pvid("eth3"),
                   "resident_mac_learned": any((row.get("mac"), row.get("vlan")) == (link["address"], 20)
                                               for row in fdb),
                   "resident_gateway": resident["status"], "guest_gateway": guest["status"],
                   "resident_interface": interface["evidence"]}
        return self.evidence("resident", "gateway", "vlan", "sw:eth1", "failed", "trunk_vlan_missing",
                             details, guest)

    def pvid(self, port):
        return next((vlan for vlan, flags in self.vlans(port).items() if "PVID" in flags), None)

    def dhcp_evidence(self):
        sleep(7)
        fresh = self.probe("guest-interface", "healthy")
        retained = self.probe("resident-interface", "healthy")
        self.probe("resident-gateway-icmp", "healthy")
        status = self.lab.command_result(*self.lab.node_args("gw", "supervisorctl", "status", "dhcp"))
        require(status.returncode == 3 and status.stdout.split()[1:2] == ["STOPPED"], "DHCP still running")
        log = self.lab.node("guest", "tail", "-n", "12", "/var/log/condonet-dhcp-client.log")
        require("broadcasting discover" in log.lower(), "No DHCP discover from the deconfigured guest")
        details = {"fresh_guest_addresses": fresh["evidence"]["addresses"], "guest_access_pvid": self.pvid("eth4"),
                   "dhcp_server_status": status.stdout.split()[1],
                   "resident_lease_retained": bool(retained["evidence"]["addresses"]), "guest_client_log": log}
        return self.evidence("guest", "dhcp", "dhcp", "gw:67", "failed", "lease_acquisition_failed",
                             details, fresh)

    def loss_evidence(self):
        target = HOST_BY_NAME["resident"].gateway
        args = self.lab.node_args("resident", "ping", "-n", "-q", "-c", "60", "-i", "0.1", "-w", "10", target)
        result = self.lab.command_result(*args)
        match = re.search(r"(\d+) packets transmitted, (\d+) received", result.stdout)
        require(result.returncode in (0, 1) and match, "No resident packet sample")
        sent, received = map(int, match.groups())
        guest = self.probe("guest-wan-http", "healthy")
        details = {"guest_canary": guest["status"], "qdisc": self.qdiscs()}
        return self.evidence("resident", "gateway", "ping_sample", target, "failed", "packet_loss",
                             details, guest, {"transmitted": sent, "received": received,
                                              "packet_loss_ratio": (sent - received) / sent})

    def policy_evidence(self, key):
        case = self.lab.cases[key]
        counter = case.evidence.replace("-", "_")
        before = self.lab.counter(counter)
        self.lab.deny(case)
        sample = self.probe("guest-wan-http", "healthy")
        details = {"counter_delta": self.lab.counter(counter) - before, "route_verified": True,
                   "control": case.control, "case": asdict(case)}
        return self.evidence(case.source, "policy", "policy",
                             f"{HOST_BY_NAME[case.destination].address}:{case.port}",
                             "expected_deny", case.id, details, sample)
