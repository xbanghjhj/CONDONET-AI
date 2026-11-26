import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from app.incident_store import IncidentStore

CATALOG = Path(__file__).resolve().parents[1] / "runbooks" / "catalog.json"


@dataclass(frozen=True)
class RunbookHit:
    id: str
    version: str
    title: str
    hypothesis: str
    target: str
    excerpt: str


class RunbookRetriever:
    def __init__(self, connection):
        self.connection = connection
        with connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS runbook_versions (
                id TEXT NOT NULL, version TEXT NOT NULL, record TEXT NOT NULL,
                PRIMARY KEY (id, version))""")
            connection.execute("""CREATE VIRTUAL TABLE IF NOT EXISTS runbooks_fts USING fts5(
                id UNINDEXED, version UNINDEXED, title, keywords, body)""")

    def load(self, path=CATALOG):
        entries = json.loads(path.read_text(encoding="utf-8"))
        inserted = 0
        with self.connection:
            for entry in entries:
                key = (entry["id"], entry["version"])
                if not re.fullmatch(r"RB0[1-6]", key[0]) or not re.fullmatch(r"\d+\.\d+\.\d+", key[1]):
                    raise ValueError("Invalid runbook ID or version")
                record = json.dumps(entry, sort_keys=True, ensure_ascii=False)
                current = self.connection.execute(
                    "SELECT record FROM runbook_versions WHERE id=? AND version=?", key).fetchone()
                if current is not None:
                    if current[0] != record:
                        raise ValueError(f"Runbook {key[0]} changed without a new version")
                    continue
                body = " ".join(entry[field] for field in ("preconditions", "proposal", "verify", "rollback"))
                self.connection.execute("INSERT INTO runbook_versions VALUES (?, ?, ?)", (*key, record))
                self.connection.execute("INSERT INTO runbooks_fts VALUES (?, ?, ?, ?, ?)",
                                        (*key, entry["title"], entry["keywords"], body))
                inserted += 1
        return inserted

    def search(self, query):
        terms = tuple(dict.fromkeys(re.findall(r"[A-Za-z0-9_]{2,}", query.lower())))[:18]
        if not terms:
            return []
        expression = " OR ".join(f'"{term}"' for term in terms)
        hits = self.connection.execute("""
            SELECT versions.record, snippet(runbooks_fts, 4, '', '', ' … ', 36)
            FROM runbooks_fts JOIN runbook_versions AS versions USING(id, version)
            WHERE runbooks_fts MATCH ?
            ORDER BY bm25(runbooks_fts, 0, 0, 2, 5, 1), versions.id, versions.version DESC
            LIMIT 3""", (expression,))
        result = []
        for record, excerpt in hits:
            entry = json.loads(record)
            result.append(RunbookHit(entry["id"], entry["version"], entry["title"],
                                     entry["hypothesis"], entry["target"], excerpt))
        return result


def main():
    parser = argparse.ArgumentParser(description="Index and query the local versioned runbooks.")
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--query", required=True)
    args = parser.parse_args()
    with IncidentStore(args.db) as store:
        retriever = RunbookRetriever(store.connection)
        inserted = retriever.load()
        print(json.dumps({"inserted": inserted, "hits": [asdict(hit) for hit in retriever.search(args.query)]}))


if __name__ == "__main__":
    main()
