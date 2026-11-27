import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from time import monotonic, sleep

from lab.topology import container_name
from runner.plans import QUARANTINE_TTL_SECONDS, RUNBOOKS


class ActionFailed(ValueError):
    pass


class LabActions:
    def __init__(self, policy, execute=subprocess.run):
        self.policy = policy
        self.execute = execute

    def command(self, argv, accepted=(0,)):
        return self.command_result(argv, accepted).stdout

    def command_result(self, argv, accepted):
        try:
            result = self.execute(argv, timeout=10, capture_output=True)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ActionFailed(f"Lab command unavailable: {argv[0]} {argv[1]}") from error
        if result.returncode not in accepted:
            diagnostic = (result.stderr or result.stdout).decode(errors="replace").strip()
            raise ActionFailed(f"Lab command failed ({result.returncode}): {diagnostic[:500]}")
        return result

    def run(self, plan, operation, accepted=(0,), approval_id=None):
        return self.command(self.policy.argv(plan, operation, approval_id), accepted)

    def inspect(self, node):
        name = container_name(self.policy.lab, node)
        rows = json.loads(self.command(("docker", "inspect", "--type", "container", name)))
        state = rows[0]
        if (state["Config"]["Labels"].get("containerlab") != self.policy.lab
                or state["HostConfig"]["NetworkMode"] != "none" or not state["State"]["Running"]):
            raise ActionFailed("Configured target is not an isolated running Containerlab node")
        return state

    def service_snapshot(self, plan):
        rule = RUNBOOKS[plan.runbook_id]
        config = self.run(plan, "config")
        status = self.run(plan, "status", (0, 3)).decode(errors="replace")
        fields = status.split()
        if len(fields) < 2 or fields[0] != rule.process:
            raise ActionFailed("Supervisor did not identify the expected service")
        pid = re.search(r"\bpid (\d+)", status)
        snapshot = {"process": fields[0], "status": fields[1], "pid": int(pid[1]) if pid else None,
                    "configuration_sha256": sha256(config).hexdigest()}
        if plan.runbook_id == "RB01":
            snapshot["fixture"] = self.command_result(
                self.policy.argv(plan, "fixture_present"), (0, 1)).returncode == 0
        return snapshot

    def quarantine_snapshot(self, plan):
        address = str(plan.parameters.source_ipv4)
        data = json.loads(self.run(plan, "list"))
        current = next((row["set"] for row in data["nftables"] if "set" in row), {})
        if (current.get("type") != "ipv4_addr" or current.get("flags") != ["timeout"]
                or current.get("timeout") != QUARANTINE_TTL_SECONDS):
            raise ActionFailed("Existing lab quarantine set does not match policy")
        elements = [item.get("elem", item) if isinstance(item, dict) else {"val": item}
                    for item in current.get("elem", [])]
        active = next((item for item in elements if item["val"] == address), None)
        if active is not None:
            active = {"timeout": current["timeout"], **active}
        data = json.loads(self.run(plan, "counter"))
        counter = next(row["counter"] for row in data["nftables"] if "counter" in row)
        return {"source_ipv4": address, "element": active, "forward_drops": counter["packets"]}

    def snapshot(self, plan):
        if plan.runbook_id == "RB03":
            return self.quarantine_snapshot(plan)
        return self.service_snapshot(plan)

    def prepare(self, plan):
        node = self.policy.validate(plan)
        rule = RUNBOOKS[plan.runbook_id]
        info = self.inspect(node)
        if plan.runbook_id == "RB03":
            self.inspect(plan.source_node)
            argv = ("docker", "exec", container_name(self.policy.lab, plan.source_node),
                    "ip", "-j", "-4", "address", "show", "dev", "eth1")
            interfaces = json.loads(self.command(argv))
            addresses = {item["local"] for interface in interfaces for item in interface["addr_info"]}
            if addresses != {str(plan.parameters.source_ipv4)}:
                raise ActionFailed("EVE source no longer owns the observed lab address")
            before = self.quarantine_snapshot(plan)
            if before["element"] is not None:
                raise ActionFailed("Source already has a quarantine element")
            return before
        if not any(mount["Destination"] == rule.mounted_path and not mount["RW"]
                   for mount in info["Mounts"]):
            raise ActionFailed("Standard configuration is not mounted read-only")
        before = self.service_snapshot(plan)
        if before["configuration_sha256"] != plan.configuration_sha256:
            raise ActionFailed("Mounted configuration differs from the approved standard")
        if before["status"] not in {"RUNNING", "STOPPED"}:
            raise ActionFailed("Supervisor state cannot be safely restored")
        self.run(plan, "validate")
        return before

    def apply(self, ticket, before):
        if ticket.plan.runbook_id == "RB03":
            self.run(ticket.plan, "add", approval_id=ticket.id)
        else:
            if before.get("fixture"):
                self.run(ticket.plan, "fixture_clear")
            self.run(ticket.plan, "start" if before["status"] == "STOPPED" else "restart")

    def rollback(self, ticket, before):
        plan = ticket.plan
        if plan.runbook_id == "RB03":
            state = self.quarantine_snapshot(plan)
            element = state["element"]
            if element is not None:
                if element.get("comment") != f"condonet-{ticket.id}":
                    raise ActionFailed("Quarantine element belongs to another change")
                self.run(plan, "delete")
            after = self.quarantine_snapshot(plan)
            if after["element"] is not None:
                raise ActionFailed("Quarantine rollback did not restore membership")
            return after
        current = self.service_snapshot(plan)
        if (current["configuration_sha256"] != before["configuration_sha256"]
                or current["status"] not in {"STOPPED", "RUNNING"}):
            raise ActionFailed("Original config or restorable process state could not be confirmed")
        fixture_changed = current.get("fixture") != before.get("fixture")
        if fixture_changed:
            self.run(plan, "fixture_restore" if before["fixture"] else "fixture_clear")
        if current["status"] != before["status"]:
            self.run(plan, "start" if before["status"] == "RUNNING" else "stop")
        elif fixture_changed and before["status"] == "RUNNING":
            self.run(plan, "restart")
        after = self.service_snapshot(plan)
        if any(after.get(key) != before.get(key) for key in ("status", "configuration_sha256", "fixture")):
            raise ActionFailed("Rollback did not restore the snapshot")
        return after

    def valid_quarantine(self, ticket, before, after):
        active = after["element"]
        return (active is not None and active.get("comment") == f"condonet-{ticket.id}"
                and active.get("timeout") == QUARANTINE_TTL_SECONDS
                and after["forward_drops"] > before["forward_drops"])

    def wait_for_expiry(self, plan, deadline):
        while True:
            state = self.quarantine_snapshot(plan)
            if state["element"] is None:
                return state
            delay = min(3, deadline - monotonic())
            if delay <= 0:
                raise ActionFailed("Quarantine element did not expire")
            sleep(delay)


class Verifier:
    CANARIES = ("admin-camera-http", "guest-wan-http")

    def __init__(self, probes):
        self.probes = probes

    def measure(self, conditions):
        with ThreadPoolExecutor(max_workers=len(conditions)) as workers:
            observations = [result.record() for result in workers.map(
                self.probes.run, (key for key, _ in conditions))]
        ok = all(self.matches(observed, key, expected)
                 for observed, (key, expected) in zip(observations, conditions, strict=True))
        return ok, observations

    def matches(self, observed, key, expected):
        probe = self.probes.probes[key]
        return (observed["probe_id"], observed["source_node"], observed["target"], observed["status"],
                observed["evidence"].get("container")) == (
                    key, probe.source_node, probe.target, expected,
                    container_name(self.probes.lab, probe.source_node))

    def repeat(self, conditions):
        observations = []
        passed = True
        for index in range(3):
            started = monotonic()
            ok, sample = self.measure(conditions)
            observations.extend(sample)
            passed &= ok
            if index < 2:
                sleep(max(0, started + 5 - monotonic()))
        return passed, observations

    def precheck(self, plan):
        if plan.runbook_id == "RB03":
            return self.restored_source(plan)
        expectations = ("failed", "healthy") if plan.runbook_id == "RB01" else ("healthy", "failed")
        probes = ("dns-udp", "portal-http")
        return self.measure(tuple((f"{plan.source_node}-{probe}", expected)
                                  for probe, expected in zip(probes, expectations, strict=True)))

    def conditions(self, plan):
        source = plan.source_node
        if plan.runbook_id == "RB03":
            return ((f"{source}-portal-http", "failed"),
                    *((probe, "healthy") for probe in self.canaries(plan)))
        targets = (f"{source}-portal-http", f"{source}-dns-udp")
        if plan.runbook_id == "RB01":
            targets += (f"{source}-dns-tcp", f"{source}-portal-name-http")
        return tuple((probe, "healthy") for probe in (*targets, *self.canaries(plan)))

    def postcheck(self, plan):
        return self.repeat(self.conditions(plan))

    def canaries(self, plan):
        if plan.runbook_id == "RB03" and plan.source_node == "admin":
            return "resident-wan-http", "guest-wan-http"
        return self.CANARIES

    def restored_source(self, plan):
        keys = (f"{plan.source_node}-portal-http", *self.canaries(plan))
        return self.measure(tuple((probe, "healthy") for probe in keys))

    def rollback_check(self, plan):
        if plan.runbook_id == "RB03":
            return self.restored_source(plan)
        return self.measure(self.conditions(plan))


class ActionRunner:
    def __init__(self, store, actions, verifier):
        self.store = store
        self.actions = actions
        self.verifier = verifier

    def __call__(self, ticket):
        plan = ticket.plan
        result = {}
        started = False
        status = "failed"
        try:
            ok, result["precheck"] = self.verifier.precheck(plan)
            if not ok:
                raise ActionFailed("Incident precheck did not confirm the action is needed")
            before = self.actions.prepare(plan)
            result["before"] = before
            self.store.record_progress(ticket, "snapshot", result)
            started = True
            self.actions.apply(ticket, before)
            applied_at = monotonic()
            self.store.record_progress(ticket, "applied", {})
            if plan.runbook_id != "RB03":
                result["after"] = self.actions.snapshot(plan)
            ok, result["postcheck"] = self.verifier.postcheck(plan)
            after = self.actions.snapshot(plan)
            result["after"] = after
            if plan.runbook_id == "RB03":
                if not ok or not self.actions.valid_quarantine(ticket, before, after):
                    raise ActionFailed("Postcheck could not confirm isolated source and working canaries")
                self.store.record_progress(ticket, "isolation_verified", result)
                result["expiry"] = self.actions.wait_for_expiry(plan, applied_at + QUARANTINE_TTL_SECONDS + 8)
                result["ttl_seconds"] = monotonic() - applied_at
                recovered, result["expiry_probes"] = self.verifier.restored_source(plan)
                if not recovered:
                    raise ActionFailed("Source or canaries did not recover after expiry")
            elif not ok or after["status"] != "RUNNING":
                raise ActionFailed("Postcheck could not confirm service recovery")
            status = "verified"
        except (ValueError, KeyError, IndexError, TypeError, StopIteration) as error:
            result["error"] = str(error)
            if started:
                try:
                    self.store.record_progress(ticket, "rollback_started", result)
                    result["rollback"] = self.actions.rollback(ticket, before)
                    result["rollback_status"] = "verified"
                    healthy, result["rollback_probes"] = self.verifier.rollback_check(plan)
                    result["baseline_healthy_after_rollback"] = healthy
                    canaries = self.verifier.canaries(plan)
                    if not all(any(self.verifier.matches(row, key, "healthy")
                                   for row in result["rollback_probes"]) for key in canaries):
                        raise ActionFailed("Canaries failed after rollback")
                except (ValueError, KeyError, IndexError, TypeError, StopIteration) as rollback_error:
                    result["rollback_status"] = "failed"
                    result["rollback_error"] = str(rollback_error)
                status = ("rolled_back" if result.get("rollback_status") == "verified"
                          and result.get("baseline_healthy_after_rollback") else "escalated")
        self.store.finish(ticket, status, result)
