import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from app.incident_store import Evidence, IncidentStore, StoredIncident
from lab.topology import HOSTS, HOST_BY_NAME

URI_SID = 1000001
SYN_SID = 1000002
SIGNATURES = {URI_SID: ("resident", "lab_alert_uri"), SYN_SID: ("admin", "lab_syn_threshold")}
PORTAL = HOST_BY_NAME["svc"].address


class EveParser:
    def __init__(self, leases):
        self.static = {host.address: host for host in HOSTS if not host.dhcp}
        self.leases = {}
        networks = [(IPv4Network(f"{host.gateway}/24", strict=False), host)
                    for host in HOSTS if host.dhcp]
        for line in leases:
            try:
                expires, _, address, *_ = line.split()
                ip = IPv4Address(address)
                expiry = int(expires)
            except ValueError:
                continue
            for network, host in networks:
                if ip in network:
                    self.leases[address] = (host, expiry)
                    break

    def source_host(self, address, timestamp):
        if address in self.static:
            return self.static[address]
        lease = self.leases.get(address)
        if lease and (lease[1] == 0 or timestamp.timestamp() < lease[1]):
            return lease[0]
        raise ValueError("source has no matching topology address or DHCP lease")

    def parse(self, line):
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError("EVE row must be a JSON object")
        if event["event_type"] != "alert":
            return None
        alert = event["alert"]
        sid = alert["signature_id"]
        if sid not in SIGNATURES:
            return None
        timestamp = datetime.fromisoformat(event["timestamp"])
        if timestamp.utcoffset() is None:
            raise ValueError("EVE timestamp needs an offset")
        utc = timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds")
        src = str(IPv4Address(event["src_ip"]))
        dst = str(IPv4Address(event["dest_ip"]))
        source = self.source_host(src, timestamp)
        expected_source, reason = SIGNATURES[sid]
        if (source.name != expected_source or event["vlan"] != [source.vlan]
                or dst != PORTAL or event["dest_port"] != 80 or event["proto"] != "TCP"
                or event["in_iface"] != "eth1" or alert["action"] != "allowed"):
            raise ValueError("alert is outside the configured test flow")
        flow = event["flow_id"]
        source_port = event["src_port"]
        if type(flow) is not int or flow <= 0 or type(source_port) is not int or not 0 < source_port <= 65535:
            raise ValueError("invalid flow ID or source port")
        uri = event.get("http", {}).get("url")
        if sid == URI_SID and uri != "/lab-alert":
            raise ValueError("URI alert does not carry the lab URI")

        identity = json.dumps((utc, flow, src, source_port, dst, 80, source.vlan, sid))
        fingerprint = hashlib.sha256(identity.encode()).hexdigest()
        details = {"sid": sid, "flow_id": flow, "interface": "eth1", "vlan": source.vlan,
                   "src_ip": src, "src_port": source_port, "dst_ip": dst, "dst_port": 80,
                   "dst_node": "svc", "uri": uri, "label": "lab_test"}
        evidence = Evidence(f"eve-{fingerprint}", utc, source.name, "portal", "eve", f"{dst}:80",
                            "alert", reason, details, {})
        incident = StoredIncident(f"ids-{fingerprint}", utc, source.name, "portal", reason,
                                  "ids_test", (evidence.id,))
        return incident, evidence


@dataclass
class IngestCounts:
    created: int = 0
    duplicates: int = 0
    ignored: int = 0
    malformed: int = 0


class EveIngestor:
    def __init__(self, parser, store):
        self.parser = parser
        self.store = store

    def ingest(self, lines):
        counts = IngestCounts()
        for line in lines:
            try:
                result = self.parser.parse(line)
            except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
                counts.malformed += 1
                continue
            if result is None:
                counts.ignored += 1
                continue
            incident, evidence = result
            if self.store.save_incident(incident, (evidence,)):
                counts.created += 1
            else:
                counts.duplicates += 1
        return counts


def main():
    parser = argparse.ArgumentParser(description="Import CondoNet test alerts from Suricata EVE.")
    parser.add_argument("--eve", type=Path, required=True)
    parser.add_argument("--leases", type=Path, required=True)
    parser.add_argument("--db", type=Path, required=True)
    args = parser.parse_args()
    with (args.leases.open(encoding="utf-8") as leases,
          args.eve.open(encoding="utf-8", errors="replace") as eve,
          IncidentStore(args.db) as store):
        counts = EveIngestor(EveParser(leases), store).ingest(eve)
    print(json.dumps(asdict(counts)))


if __name__ == "__main__":
    main()
