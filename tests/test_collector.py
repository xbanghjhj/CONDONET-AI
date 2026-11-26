import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from app.collector import Collector
from runner.read_tools import Probe, ProbeResult

PORTAL = Probe("resident-portal-http", "resident", "portal", "http", "10.60.50.10", 80)
GATEWAY = Probe("guest-gateway-icmp", "guest", "gateway", "ping", "10.60.30.1")
START = datetime(2026, 1, 1, tzinfo=timezone.utc)


class FakeRunner:
    def __init__(self, probe):
        self.probes = {probe.id: probe}
        self.results = []

    def run(self, probe_id):
        self.probes[probe_id]
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class CollectorTest(unittest.TestCase):
    def configure(self, probe=PORTAL):
        self.probe = probe
        self.runner = FakeRunner(probe)
        self.events = []
        self.collector = Collector(self.runner, lambda kind, row: self.events.append((kind, row)),
                                   (probe.id,))

    def sample(self, tick, status="failed", reason="connection_failure"):
        result = ProbeResult.observed(self.probe, status, reason)
        self.runner.results.append(replace(result, timestamp=START + timedelta(seconds=tick)))
        self.collector.poll()
        return result.id

    def incidents(self):
        return [row for kind, row in self.events if kind == "incidents"]

    def test_three_failures_open_one_incident_and_later_failures_deduplicate(self):
        self.configure()
        self.assertEqual(self.incidents(), [])
        first = self.sample(0)
        self.assertEqual(self.incidents(), [])
        second = self.sample(10)
        self.assertEqual(self.incidents(), [])
        third = self.sample(20)
        opened, = self.incidents()
        self.assertEqual(opened["event"], "incident_opened")
        self.assertEqual(opened["source_node"], "resident")
        self.assertEqual(opened["evidence_ids"], [first, second, third])
        self.sample(30)
        deduplicated = self.incidents()[-1]
        self.assertEqual(deduplicated["event"], "incident_deduplicated")
        self.assertEqual(deduplicated["id"], opened["id"])

    def test_healthy_missing_deny_and_reason_change_break_the_streak(self):
        for status, reason in (("healthy", "http_response"), ("missing", "runner_error"),
                               ("expected_deny", "policy"), ("failed", "http_status")):
            with self.subTest(status=status, reason=reason):
                self.configure()
                self.sample(0)
                self.sample(10)
                self.sample(20, status, reason)
                self.sample(30)
                self.sample(40)
                self.assertEqual(self.incidents(), [])
                self.sample(50)
                self.assertEqual(len(self.incidents()), 1)

    def test_runner_exception_records_missing_and_breaks_the_streak(self):
        self.configure()
        self.sample(0)
        self.sample(10)
        self.runner.results.append(RuntimeError("runner unavailable"))
        missing, = self.collector.poll()
        self.assertEqual((missing.status, missing.reason), ("missing", "runner_exception"))
        self.assertEqual(missing.evidence, {"error_type": "RuntimeError"})
        self.sample(30)
        self.sample(40)
        self.assertEqual(self.incidents(), [])

    def test_elapsed_gap_breaks_the_streak_and_dedup_expires(self):
        self.configure()
        for tick in (0, 10, 50, 60):
            self.sample(tick)
        self.assertEqual(self.incidents(), [])
        self.sample(70)
        first_id = self.incidents()[-1]["id"]
        self.sample(80, "healthy", "http_response")
        recovered = self.incidents()[-1]
        self.assertEqual((recovered["event"], recovered["id"]), ("incident_recovered", first_id))
        for tick in (180, 190, 200):
            self.sample(tick)
        reopened = self.incidents()[-1]
        self.assertEqual(reopened["event"], "incident_opened")
        self.assertNotEqual(reopened["id"], first_id)

    def test_missing_does_not_resolve_and_healthy_resolves_once(self):
        self.configure()
        for tick in (0, 10, 20):
            self.sample(tick)
        self.sample(30, "missing", "runner_timeout")
        self.assertEqual([row["event"] for row in self.incidents()], ["incident_opened"])
        self.sample(40, "healthy", "http_response")
        self.sample(50, "healthy", "http_response")
        self.assertEqual([row["event"] for row in self.incidents()],
                         ["incident_opened", "incident_recovered"])

    def test_gateway_ping_failure_alone_does_not_open_incident(self):
        self.configure(GATEWAY)
        for tick in (0, 10, 20, 30):
            self.sample(tick, "failed", "icmp_unreachable")
        self.assertEqual(self.incidents(), [])


if __name__ == "__main__":
    unittest.main()
