import subprocess
import unittest
from unittest.mock import Mock

from runner.read_tools import ReadOnlyRunner


class ReadOnlyRunnerTest(unittest.TestCase):
    def setUp(self):
        self.execute = Mock()
        self.runner = ReadOnlyRunner("condonet-test", execute=self.execute)

    def test_rejects_unlisted_actions_and_invalid_lab(self):
        for probe in ("guest-portal-http", "guest-camera-tcp", "guest-interface;id", "wan-interface"):
            with self.subTest(probe=probe), self.assertRaises(ValueError):
                self.runner.run(probe)
        with self.assertRaises(ValueError):
            ReadOnlyRunner("lab; id")
        self.execute.assert_not_called()

    def test_fixed_argv_uses_policy_source_and_lab_destination(self):
        self.execute.return_value = subprocess.CompletedProcess([], 0, "CondoNet Portal\n200 0.01", "")
        result = self.runner.run("resident-portal-http")
        argv = self.execute.call_args.args[0]
        self.assertEqual(argv[:5], ("docker", "exec", "--env", "LC_ALL=C", "clab-condonet-test-resident"))
        self.assertEqual(argv[-1], "http://10.60.50.10:80/")
        self.assertNotIn("shell", self.execute.call_args.kwargs)
        self.assertEqual(result.status, "healthy")
        self.assertEqual(result.record()["source_node"], "resident")
        self.assertEqual(result.timestamp.utcoffset().total_seconds(), 0)

    def test_http_success_requires_status_and_body(self):
        for output, reason in (("Unexpected\n200 0.01", "http_body_mismatch"),
                               ("CondoNet Portal\n503 0.01", "http_status")):
            with self.subTest(reason=reason):
                self.execute.return_value = subprocess.CompletedProcess([], 0, output, "")
                result = self.runner.run("resident-portal-http")
                self.assertEqual((result.status, result.reason), ("failed", reason))

    def test_tool_timeout_and_runner_timeout_are_distinct(self):
        self.execute.return_value = subprocess.CompletedProcess([], 28, "\n000 4.0", "")
        result = self.runner.run("guest-wan-http")
        self.assertEqual((result.status, result.reason), ("failed", "probe_timeout"))
        self.assertNotIn("http_status", result.measurements)
        self.execute.side_effect = subprocess.TimeoutExpired("docker", 6)
        result = self.runner.run("guest-wan-http")
        self.assertEqual((result.status, result.reason), ("missing", "runner_timeout"))

    def test_docker_failure_is_missing(self):
        self.execute.return_value = subprocess.CompletedProcess([], 1, "", "Error response from daemon")
        result = self.runner.run("admin-gateway-icmp")
        self.assertEqual((result.status, result.reason), ("missing", "runner_error"))
        self.assertEqual(result.measurements, {})
