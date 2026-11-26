import json
import unittest
from dataclasses import asdict

from app.eve_ingest import EveIngestor, EveParser
from app.incident_store import IncidentStore


class EveTest(unittest.TestCase):
    def setUp(self):
        self.event = {
            "event_type": "alert", "timestamp": "2026-11-26T12:00:00.123456+0000",
            "flow_id": 42, "in_iface": "eth1", "proto": "TCP", "vlan": [20],
            "src_ip": "10.60.20.144", "src_port": 45312, "dest_ip": "10.60.50.10",
            "dest_port": 80, "alert": {"signature_id": 1000001, "action": "allowed"},
            "http": {"url": "/lab-alert"},
        }
        self.parser = EveParser(["1795709000 aa:c1:ab:58:c1:e9 10.60.20.144 * *"])

    def test_entry_persists_and_replays_once(self):
        with IncidentStore(":memory:") as store:
            ingest = EveIngestor(self.parser, store)
            result = ingest.ingest(["{bad", '{"event_type":"http"}', json.dumps(self.event),
                                    json.dumps(self.event, sort_keys=True)])
            self.assertEqual(asdict(result), {"created": 1, "duplicates": 1, "ignored": 1, "malformed": 1})
            incident, evidence = self.parser.parse(json.dumps(self.event))
            self.assertEqual(store.get_incident(incident.id), incident)
            self.assertEqual(store.get_evidence(evidence.id), evidence)
            self.assertEqual(evidence.evidence["label"], "lab_test")
            self.assertEqual(evidence.source_node, "resident")
            self.assertTrue(evidence.timestamp.endswith("+00:00"))

    def test_alert_without_matching_lease_or_vlan_is_malformed(self):
        off_vlan = {**self.event, "vlan": [50]}
        unknown_ip = {**self.event, "src_ip": "10.60.20.145"}
        with IncidentStore(":memory:") as store:
            result = EveIngestor(self.parser, store).ingest(map(json.dumps, [off_vlan, unknown_ip]))
            self.assertEqual((result.created, result.malformed), (0, 2))

    def test_syn_identifies_admin_without_dhcp(self):
        event = {**self.event, "src_ip": "10.60.10.10", "vlan": [10],
                 "alert": {"signature_id": 1000002, "action": "allowed"}}
        _, evidence = self.parser.parse(json.dumps(event))
        self.assertEqual(evidence.source_node, "admin")
