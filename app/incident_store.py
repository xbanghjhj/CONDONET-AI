import json
import sqlite3
from dataclasses import asdict, dataclass, fields, replace


@dataclass(frozen=True)
class Evidence:
    id: str
    timestamp: str
    source_node: str
    service: str
    probe: str
    target: str
    status: str
    reason: str
    evidence: dict
    measurements: dict
    probe_id: str | None = None

    @classmethod
    def from_record(cls, record):
        return cls(**{field.name: record[field.name] for field in fields(cls) if field.name in record})


@dataclass(frozen=True)
class StoredIncident:
    id: str
    timestamp: str
    source_node: str
    service: str
    reason: str
    origin: str
    evidence_ids: tuple[str, ...]
    status: str = "open"


class IncidentStore:
    def __init__(self, path):
        self.connection = sqlite3.connect(path, timeout=5)
        with self.connection:
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, record TEXT NOT NULL)")
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, record TEXT NOT NULL)")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.connection.close()

    def save_evidence(self, item):
        with self.connection:
            self.connection.execute("INSERT OR IGNORE INTO evidence VALUES (?, ?)",
                                    (item.id, json.dumps(asdict(item))))

    def save_incident(self, incident, evidence=()):
        with self.connection:
            self.connection.executemany(
                "INSERT OR IGNORE INTO evidence VALUES (?, ?)",
                ((item.id, json.dumps(asdict(item))) for item in evidence))
            cursor = self.connection.execute("INSERT OR IGNORE INTO incidents VALUES (?, ?)",
                                             (incident.id, json.dumps(asdict(incident))))
        return cursor.rowcount == 1

    def get_evidence(self, evidence_id):
        row = self.connection.execute("SELECT record FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        return Evidence(**json.loads(row[0])) if row else None

    def get_incident(self, incident_id):
        row = self.connection.execute("SELECT record FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if row is None:
            return None
        record = json.loads(row[0])
        record["evidence_ids"] = tuple(record["evidence_ids"])
        return StoredIncident(**record)

    def record_collector(self, stream, record):
        if stream == "probes":
            self.save_evidence(Evidence.from_record(record))
        elif record["event"] == "incident_opened":
            incident = StoredIncident(record["id"], record["timestamp"], record["source_node"],
                                      record["service"], record["reason"], "collector",
                                      tuple(record["evidence_ids"]))
            self.save_incident(incident)
        elif record["event"] == "incident_recovered":
            incident = self.get_incident(record["id"])
            if incident:
                evidence = tuple(dict.fromkeys((*incident.evidence_ids, *record["evidence_ids"])))
                recovered = replace(incident, status="recovered", evidence_ids=evidence)
                with self.connection:
                    self.connection.execute("UPDATE incidents SET record = ? WHERE id = ?",
                                            (json.dumps(asdict(recovered)), incident.id))
