import argparse
import json
import signal
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Lock, Thread
from time import monotonic
from uuid import uuid4

from app.incident_store import IncidentStore
from app.metrics import METRICS_ADDRESS, MetricsServer
from runner.read_tools import MONITORED_PROBES, ProbeResult, ReadOnlyRunner

SAMPLE_INTERVAL = 10
STALE_AFTER = 25
FAILURE_THRESHOLD = 3
DEDUP_WINDOW = 120
INCIDENT_PROBES = {"http", "dns"}


@dataclass
class Incident:
    id: str
    last_qualified_at: float
    active: bool = True


class JsonlEvidence:
    def __init__(self, output, store=None):
        output.mkdir(parents=True, exist_ok=False)
        self.output = output
        self.store = store

    def __call__(self, stream, record):
        with (self.output / f"{stream}.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        if self.store is not None:
            self.store.record_collector(stream, record)


class Collector:
    def __init__(self, runner, emit, probe_ids=MONITORED_PROBES):
        self.runner = runner
        self.emit = emit
        self.probes = tuple(runner.probes[probe_id] for probe_id in probe_ids)
        if not self.probes or len({probe.labels for probe in self.probes}) != len(self.probes):
            raise ValueError("Collector needs at least one probe and unique metric labels")
        self.latest = {}
        self.streaks = {}
        self.incidents = {}
        self.poll_lock = Lock()
        self.state_lock = Lock()

    def collect_probe(self, probe):
        try:
            result = self.runner.run(probe.id)
        except Exception as error:
            return ProbeResult.observed(probe, "missing", "runner_exception",
                                        {"error_type": type(error).__name__})
        if (not isinstance(result, ProbeResult) or result.probe != probe
                or result.status not in {"healthy", "failed", "missing", "expected_deny"}):
            return ProbeResult.observed(probe, "missing", "invalid_runner_result")
        return result

    @staticmethod
    def incident_event(event, incident, result, reason, evidence_ids):
        return {
            "event": event, "id": incident.id, "timestamp": result.record()["timestamp"],
            "source_node": result.probe.source_node, "service": result.probe.service,
            "probe": result.probe.tool, "reason": reason, "evidence_ids": evidence_ids,
        }

    def track_incident(self, result):
        probe = result.probe
        previous = self.latest.get(probe.id)
        if result.status != "failed" or probe.tool not in INCIDENT_PROBES:
            self.streaks.pop(probe.id, None)
            events = []
            if result.status == "healthy" and probe.tool in INCIDENT_PROBES:
                for (source, service, reason), incident in self.incidents.items():
                    if incident.active and (source, service) == probe.labels[:2]:
                        incident.active = False
                        events.append(self.incident_event("incident_recovered", incident,
                                                          result, reason, [result.id]))
            return None, events

        age = (result.timestamp - previous.timestamp).total_seconds() if previous else None
        if (previous is None or previous.status != "failed" or previous.reason != result.reason
                or not 0 <= age <= STALE_AFTER):
            self.streaks[probe.id] = deque(maxlen=FAILURE_THRESHOLD)
        streak = self.streaks.setdefault(probe.id, deque(maxlen=FAILURE_THRESHOLD))
        streak.append(result.id)
        if len(streak) < FAILURE_THRESHOLD:
            return None, ()

        key = (*probe.labels[:2], result.reason)
        incident = self.incidents.get(key)
        timestamp = result.timestamp.timestamp()
        if incident and 0 <= timestamp - incident.last_qualified_at <= DEDUP_WINDOW:
            incident.last_qualified_at = timestamp
            incident.active = True
            event = "incident_deduplicated"
        else:
            incident = Incident(uuid4().hex, timestamp)
            self.incidents[key] = incident
            event = "incident_opened"
        return incident.id, (self.incident_event(event, incident, result, result.reason, list(streak)),)

    def poll(self):
        with self.poll_lock:
            with ThreadPoolExecutor(max_workers=len(self.probes)) as workers:
                results = tuple(workers.map(self.collect_probe, self.probes))
            with self.state_lock:
                for result in results:
                    incident_id, events = self.track_incident(result)
                    self.latest[result.probe.id] = result
                    record = result.record()
                    if incident_id:
                        record["incident_id"] = incident_id
                    self.emit("probes", record)
                    for event in events:
                        self.emit("incidents", event)
            return results

    def snapshot(self):
        with self.state_lock:
            return tuple((probe, self.latest.get(probe.id)) for probe in self.probes)

    def run(self, stop):
        deadline = monotonic()
        while not stop.is_set():
            self.poll()
            deadline += SAMPLE_INTERVAL
            now = monotonic()
            if deadline <= now:
                missed = int((now - deadline) // SAMPLE_INTERVAL) + 1
                deadline += missed * SAMPLE_INTERVAL
            stop.wait(deadline - now)


def collect(args, store=None):
    runner = ReadOnlyRunner(args.lab)
    collector = Collector(runner, JsonlEvidence(args.out_dir, store))
    if args.once:
        collector.poll()
        return

    stop = Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    with MetricsServer(collector, STALE_AFTER) as server:
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            address, port = METRICS_ADDRESS
            print(f"Collecting {args.lab} every {SAMPLE_INTERVAL}s into {args.out_dir}. "
                  f"Metrics at http://{address}:{port}/metrics", flush=True)
            collector.run(stop)
        finally:
            server.shutdown()
            worker.join()


def main():
    parser = argparse.ArgumentParser(description="Collect read-only CondoNet lab probes.")
    parser.add_argument("--lab", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--incident-db", type=Path)
    args = parser.parse_args()
    try:
        if args.incident_db:
            with IncidentStore(args.incident_db) as store:
                collect(args, store)
        else:
            collect(args)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
