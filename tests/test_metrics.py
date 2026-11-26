import unittest
from dataclasses import replace
from datetime import datetime, timezone

from app.collector import STALE_AFTER
from app.metrics import render_metrics
from runner.read_tools import Probe, ProbeResult

PORTAL = Probe("resident-portal-http", "resident", "portal", "http", "10.60.50.10", 80)
LABELS = 'source_node="resident",service="portal",probe="http"'
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class MetricsTest(unittest.TestCase):
    def render(self, status, samples, age=0):
        result = ProbeResult.observed(PORTAL, status, "test", measurements=samples)
        result = replace(result, timestamp=NOW)
        return render_metrics(((PORTAL, result),), STALE_AFTER, NOW.timestamp() + age)

    def test_healthy_service_exports_measured_values_and_stable_labels(self):
        output = self.render("healthy", {"http_status": 200, "http_body_match": 1,
                                         "http_latency_seconds": 0.01})
        self.assertIn(f"condonet_availability{{{LABELS}}} 1\n", output)
        self.assertIn(f"condonet_http_status{{{LABELS}}} 200\n", output)
        self.assertIn(f"condonet_http_latency_seconds{{{LABELS}}} 0.01\n", output)
        self.assertNotIn("id=", output)

    def test_connection_failure_emits_zero_availability_without_http_status(self):
        output = self.render("failed", {})
        self.assertIn(f"condonet_availability{{{LABELS}}} 0\n", output)
        self.assertIn(f"condonet_probe_sample_present{{{LABELS}}} 1\n", output)
        self.assertNotIn("condonet_http_status", output)

    def test_missing_stale_and_expected_deny_do_not_emit_service_measurements(self):
        for state, age, displayed in (("missing", 0, "missing"),
                                      ("healthy", STALE_AFTER + 1, "stale"),
                                      ("expected_deny", 0, "expected_deny")):
            with self.subTest(state=state, age=age):
                output = self.render(state, {"http_status": 200}, age)
                self.assertIn(f'condonet_probe_state{{{LABELS},state="{displayed}"}} 1\n', output)
                self.assertNotIn("condonet_availability", output)
                self.assertNotIn("condonet_http_status", output)

    def test_never_observed_probe_has_no_sample_timestamp(self):
        output = render_metrics(((PORTAL, None),), STALE_AFTER, NOW.timestamp())
        self.assertIn(f"condonet_probe_sample_present{{{LABELS}}} 0\n", output)
        self.assertNotIn("condonet_probe_sample_timestamp_seconds", output)
