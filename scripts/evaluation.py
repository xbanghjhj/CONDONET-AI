import argparse
import csv
import fcntl
import json
import signal
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Thread
from time import monotonic_ns
from uuid import uuid4

import httpx
import yaml

from app.collector import Collector, JsonlEvidence, MONITORED_PROBES, STALE_AFTER
from app.eve_ingest import EveIngestor, EveParser
from app.incident_store import IncidentStore, StoredIncident
from app.metrics import MetricsServer
from lab.faults import LabFaults
from lab.policy import CheckFailed, load_cases, require
from lab.topology import HOST_BY_NAME
from runner.plans import APPROVAL_TTL_SECONDS
from scripts.evaluation_runtime import EvaluationRuntime, wait_for
from scripts.verify import LabVerifier

ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "results/runs.csv"
CSV_FIELDS = CSV_PATH.open(encoding="utf-8").readline().strip().split(",")
TERMINAL = {"verified", "failed", "rolled_back", "escalated", "rejected", "expired"}
TIMINGS = {"detection": ("injected", "detected"), "diagnosis": ("detected", "diagnosed"),
           "approval_wait": ("proposed", "approved"), "verification": ("applied", "verified"),
           "end_to_end": ("injected", "verified")}
BASELINE = ("resident-gateway-icmp", "guest-gateway-icmp", "resident-dns-udp", "guest-dns-udp",
            "resident-portal-http", "resident-portal-name-http", "admin-camera-http", "guest-wan-http")


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    truth: str
    source: str | None = None
    runbook: str | None = None


def slots():
    data = yaml.safe_load((ROOT / "tests/scenarios.yaml").read_text(encoding="utf-8"))
    cases = {row["id"]: Scenario(**row) for row in data["scenarios"]}
    rounds = data["rounds"]
    require(len(data["scenarios"]) == len(cases) == 8 and set(cases) == {f"{n:02}" for n in range(1, 9)},
            "Expected eight unique scenarios")
    require(len(rounds) == 3 and all(len(order) == 8 and set(order) == cases.keys() for order in rounds)
            and len({tuple(order) for order in rounds}) == 3, "Expected three distinct complete rounds")
    return {f"r{index}-{key}": cases[key] for index, order in enumerate(rounds, 1) for key in order}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def write_json(path, payload):
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


@dataclass
class Trial:
    slot: str
    case: Scenario
    directory: Path
    run_id: str
    clocks: dict = field(default_factory=dict)
    row: dict = field(default_factory=dict)

    def stamp(self, name, utc=None, tick=None):
        self.row[f"{name}_at"] = utc or utc_now()
        self.clocks[name] = monotonic_ns() if tick is None else tick

    def record(self):
        for label, (first, last) in TIMINGS.items():
            if first in self.clocks and last in self.clocks:
                elapsed = self.clocks[last] - self.clocks[first]
                if elapsed >= 0:
                    self.row[f"{label}_seconds"] = round(elapsed / 1e9, 3)
        result = {"test_id": self.case.id, "slot_id": self.slot, "run_id": self.run_id,
                  "ground_truth": self.case.truth, "evidence": str(self.directory.relative_to(ROOT)),
                  **self.row}
        write_json(self.directory / "trial.json", {"row": result, "monotonic_ns": self.clocks})
        return result


class Evaluation:
    def __init__(self, args, runtime):
        self.args = args
        self.runtime = runtime
        self.verifier = LabVerifier(args.lab, args.output, load_cases())
        self.faults = LabFaults(self.verifier, args.eve)
        self.runner = self.faults.probes
        self.interrupted = False

    def baseline(self, trial, label):
        self.verifier.vlan()
        self.verifier.quarantine_empty()
        checks = [self.faults.probe(key, "healthy") for key in BASELINE]
        for name in ("dns", "nginx"):
            checks.append({"program": name, "status": self.faults.service("svc", "status", name)})
        for name, node in (("dhcp", "gw"), ("dhcp-client", "guest"), ("dhcp-client", "resident")):
            checks.append({"program": f"{node}/{name}", "status": self.faults.service(node, "status", name)})
        require(all(row["kind"] == "noqueue" for row in self.faults.qdiscs()), "Resident qdisc differs from baseline")
        write_json(trial.directory / f"{label}.json", checks)
        trial.row[f"{label}_checks"] = f"{label}.json"
        return checks

    def read_incidents(self, trial):
        path = trial.directory / "collector" / "incidents.jsonl"
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines(keepends=True):
                if line.endswith("\n"):
                    yield json.loads(line)

    def collect_network(self, trial):
        case = trial.case
        if case.id == "07":
            self.verifier.routing()
        evidence = self.faults.network_evidence(case.id)
        incident = StoredIncident(uuid4().hex, utc_now(), case.source, evidence[0].service,
                                  evidence[0].reason, "lab_observation", tuple(item.id for item in evidence))
        with IncidentStore(self.runtime.incidents) as store:
            store.save_incident(incident, evidence)
        trial.stamp("detected", incident.timestamp)
        return incident.id

    def collect_service(self, trial):
        case = trial.case
        expected = "dns" if case.id == "01" else "portal"
        if case.id == "01":
            wrong = self.faults.probe("resident-dns-udp", "failed")
            require(wrong["reason"] == "dns_answer_mismatch" and wrong["evidence"]["answers"] == ["10.60.50.11"],
                    "DNS did not return the fixture's wrong A record")
            self.faults.probe("resident-portal-http", "healthy")
            self.faults.probe("resident-portal-name-http", "failed")
        else:
            for key, status in (("resident-dns-udp", "healthy"), ("resident-portal-tcp", "failed"),
                                ("resident-portal-http", "failed")):
                self.faults.probe(key, status)
        def detect():
            return next((row for row in self.read_incidents(trial)
                         if row["event"] == "incident_opened" and row["service"] == expected
                         and row["source_node"] == case.source and
                         row["monotonic_ns"] >= trial.clocks["injected"]), None)
        incident = wait_for(detect, 65, f"Collector did not detect resident {expected} failure")
        trial.stamp("detected", incident["recorded_at"], incident["monotonic_ns"])
        return incident["id"]

    def collect_eve(self, trial, offset):
        leases = self.verifier.node("gw", "cat", "/var/lib/misc/condonet-dhcp.leases").splitlines()
        parser = EveParser(leases)
        def alert():
            with self.args.eve.open("rb") as log:
                log.seek(offset)
                for line in log:
                    if not line.endswith(b"\n"):
                        break
                    try:
                        parsed = parser.parse(line)
                    except (ValueError, KeyError, TypeError):
                        continue
                    if parsed and parsed[0].source_node == trial.case.source:
                        return line.decode(), parsed
            return None
        line, (incident, evidence) = wait_for(alert, 35, "Live resident EVE alert did not arrive")
        addresses = self.verifier.ipv4("resident", "eth1")
        require({address for address, _ in addresses} == {evidence.evidence["src_ip"]}, "EVE source IP mismatch")
        (trial.directory / "eve.jsonl").write_text(line, encoding="utf-8")
        with IncidentStore(self.runtime.incidents) as store:
            counts = EveIngestor(parser, store).ingest([line])
        require(counts.created == 1, "Live EVE event did not create exactly one incident")
        trial.stamp("detected")
        return incident.id

    def observe_normal(self, trial, collector):
        require(self.args.eve is not None and self.args.eve.is_file(), "Normal case requires the live EVE log")
        offset = self.args.eve.stat().st_size
        stop_at = monotonic_ns() + 60_000_000_000
        wait_for(lambda: monotonic_ns() >= stop_at, 61, "Baseline observation was interrupted")
        samples = (trial.directory / "collector" / "probes.jsonl").read_text(encoding="utf-8")
        records = [json.loads(line) for line in samples.splitlines(keepends=True) if line.endswith("\n")]
        require(len(records) >= 6 * len(MONITORED_PROBES)
                and all(row["status"] == "healthy" for row in records)
                and all(result and result.status == "healthy" for _, result in collector.snapshot()),
                "Normal baseline did not have 60 s of healthy samples")
        require(not list(self.read_incidents(trial)), "Unexpected incident in normal baseline")
        with self.args.eve.open("rb") as eve:
            eve.seek(offset)
            require(all(json.loads(line).get("event_type") != "alert" for line in eve if line.endswith(b"\n")),
                    "Unexpected IDS alert in normal baseline")
        trial.row["predicted_class"] = "normal"

    def record_action(self, trial, detail):
        approval = detail["approval"]
        audit = detail["audit"]
        write_json(trial.directory / "action.json", detail)
        if approval:
            trial.row["action_id"] = approval["id"]
        for event in audit:
            field = {"pending": "proposed", "approved": "approved", "applied": "applied",
                     "verified": "verified"}.get(event["event"])
            if field:
                trial.stamp(field, event["utc"], event["monotonic_ns"])
        if approval and approval["result"]:
            trial.row["ttl_seconds"] = approval["result"].get("ttl_seconds")
        events = [row["event"] for row in audit]
        if "claimed" in events:
            result = approval["result"] or {}
            required = {"pending", "approved", "claimed", "snapshot", "applied"}
            trial.row["audit_complete"] = (required <= set(events) and bool(result.get("before"))
                                           and bool(result.get("after"))
                                           and all(row["plan_hash"] == approval["plan_hash"] for row in audit)
                                           and events[-1] in TERMINAL and events.count("claimed") == 1)

    def review(self, trial, incident_id, detail):
        path = f"/incidents/{incident_id}/action"
        self.record_action(trial, detail)
        require(detail["proposal"] and detail["approval"]["status"] == "pending"
                and detail["proposal"]["plan"]["runbook_id"] == trial.case.runbook
                and not detail["review_blockers"], "Expected a complete reviewable runbook proposal")
        print(f"REVIEW {trial.slot} {incident_id} {trial.case.runbook} {self.runtime.ui_url}", flush=True)
        def action_progress():
            state = self.runtime.query("GET", path)
            status = state["approval"]["status"]
            if status in TERMINAL:
                return state
            return None

        state = wait_for(action_progress, APPROVAL_TTL_SECONDS + 155, "Action did not reach a terminal state")
        self.record_action(trial, state)
        require(state["approval"]["status"] == "verified",
                f"Operator approval/action ended in {state['approval']['status']}")
        require(trial.row.get("audit_complete") is True, "Incomplete remediation audit")
        if trial.case.id == "06":
            require(119 <= trial.row["ttl_seconds"] <= 128, "RB03 expiry outside the measured 120 s window")

    def evaluate(self, trial, collector):
        case = trial.case
        if case.id == "08":
            self.observe_normal(trial, collector)
            return
        with self.faults.inject(case.id, lambda: trial.stamp("injected")) as offset:
            try:
                self.assess_incident(trial, offset)
            except KeyboardInterrupt:
                self.runtime.close()
                raise

    def assess_incident(self, trial, offset):
        case = trial.case
        if case.id in {"01", "02"}:
            incident_id = self.collect_service(trial)
        elif case.id == "06":
            incident_id = self.collect_eve(trial, offset)
        else:
            incident_id = self.collect_network(trial)
        trial.row["incident_id"] = incident_id
        detail = self.runtime.query("POST", f"/incidents/{incident_id}/investigate")
        agent = detail["agent"] or {}
        trial.stamp("diagnosed", agent.get("completed_at"), agent.get("completed_monotonic_ns"))
        write_json(trial.directory / "incident.json", detail)
        decision = agent.get("decision")
        trial.row["predicted_class"] = decision["hypothesis"] if decision else "unknown"
        require(trial.row["predicted_class"] == case.truth,
                f"Expected {case.truth}, got {trial.row['predicted_class']}")
        if case.runbook:
            self.review(trial, incident_id, detail)
        else:
            require(detail["approval"] is None, "A read-only diagnosis issued an action")

    def run(self, trial):
        trial.directory.mkdir(mode=0o700)
        trial.stamp("started")
        stop = Event()
        with (trial.directory / "checks.log").open("w", encoding="utf-8") as self.verifier.log:
            try:
                before = self.baseline(trial, "before")
            except KeyboardInterrupt:
                self.interrupted = True
                trial.row.update(verdict="NOT RUN", reason="Interrupted during baseline")
                return trial.record()
            except (CheckFailed, OSError, ValueError, subprocess.TimeoutExpired) as error:
                trial.row.update(verdict="NOT RUN", reason=f"Baseline failed: {error}")
                return trial.record()
            try:
                def collect():
                    with IncidentStore(self.runtime.incidents) as store:
                        collector.emit.store = store
                        collector.run(stop)
                collector = Collector(self.runner, JsonlEvidence(trial.directory / "collector"))
                worker = Thread(target=collect)
                with MetricsServer(collector, STALE_AFTER) as metrics:
                    server = Thread(target=metrics.serve_forever)
                    server.start()
                    worker.start()
                    try:
                        response = self.runtime.client.get("/metrics")
                        response.raise_for_status()
                        require("condonet_probe_" in response.text, "API returned no collector metrics")
                        (trial.directory / "metrics.prom").write_text(response.text, encoding="utf-8")
                        self.evaluate(trial, collector)
                        trial.row["verdict"] = "PASS"
                    finally:
                        stop.set()
                        worker.join(timeout=12)
                        metrics.shutdown()
                        server.join()
                if trial.case.id in {"01", "02"}:
                    require(trial.clocks["detected"] - trial.clocks["injected"] <= 60_000_000_000,
                            "Service detection exceeded 60 seconds")
            except KeyboardInterrupt:
                self.interrupted = True
                trial.row.update(verdict="FAIL", reason="Interrupted before verdict")
            except (CheckFailed, OSError, ValueError, KeyError, TypeError, httpx.HTTPError,
                    subprocess.TimeoutExpired) as error:
                trial.row.update(verdict="FAIL", reason=str(error))
            finally:
                try:
                    if trial.case.id == "04":
                        self.verifier.lease(HOST_BY_NAME["guest"])
                    after = self.baseline(trial, "after")
                    if trial.case.id == "02":
                        dns = lambda checks: next(row["status"].split(", uptime")[0] for row in checks
                                                  if row.get("program") == "dns")
                        require(dns(before) == dns(after), "Nginx trial restarted DNS")
                except (CheckFailed, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
                    previous = trial.row.get("reason", "")
                    trial.row.update(verdict="FAIL", reason=f"{previous} Reset verification failed: {error}".strip())
                    trial.row.pop("after_checks", None)
        return trial.record()


def main():
    parser = argparse.ArgumentParser(description="Evaluate the local CondoNet Containerlab; review only via the operator UI/API.")
    parser.add_argument("--lab", required=True)
    parser.add_argument("--eve", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ui-port", type=int)
    parser.add_argument("--slot", action="append")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: signal.raise_signal(signal.SIGINT))
    matrix = slots()
    if args.slot and (len(set(args.slot)) != len(args.slot) or not set(args.slot) <= matrix.keys()):
        parser.error("Unknown or duplicate slot")
    args.output = args.output.resolve()
    if not args.output.is_relative_to(ROOT / "evidence"):
        parser.error("Use a fresh output directory below evidence/")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    lock_path = ROOT / "evidence" / f".{args.lab}.lock"
    if not args.lab.startswith(("condonet-day09", "condonet-day10")) or "/" in args.lab:
        parser.error("Use a dedicated Day 9 or Day 10 lab name")
    with lock_path.open("a") as lock, (args.output / "runs.csv").open("w", newline="", encoding="utf-8") as output:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        output.flush()
        succeeded = True
        with EvaluationRuntime(args.lab, args.output, args.ui_port) as runtime:
            evaluation = Evaluation(args, runtime)
            with (args.output / "scope.log").open("w", encoding="utf-8") as evaluation.verifier.log:
                evaluation.verifier.topology()
            print(f"UI {runtime.ui_url}", flush=True)
            for slot in args.slot or matrix:
                run_id = f"{slot}-{uuid4().hex[:12]}"
                trial = Trial(slot, matrix[slot], args.output / run_id, run_id)
                record = evaluation.run(trial)
                writer.writerow(record)
                output.flush()
                succeeded &= record["verdict"] == "PASS"
                print(slot, run_id, record["verdict"], record.get("reason", ""), flush=True)
                if evaluation.interrupted:
                    return 130
                if "after_checks" not in record:
                    return 1
    return 0 if succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
