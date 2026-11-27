import json
from functools import cached_property
from pathlib import Path


ACTION_AUDIT = "action-audit.json"


def write_json(path, payload):
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


class EvidenceStore:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.directory = self.root / "evidence"

    def scope(self, path):
        candidate = (self.root / path).resolve()
        if not candidate.is_relative_to(self.directory):
            raise ValueError(f"Evidence path is outside {self.directory}: {path}")
        return candidate

    @cached_property
    def archive(self):
        manifest = self.scope(self.directory / "migration-manifest.json")
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        return {row["old"]: row["new"] for row in data["files"]}

    def locate(self, path):
        candidate = self.scope(path)
        if candidate.exists():
            return candidate
        moved = self.archive.get(candidate.relative_to(self.root).as_posix())
        return self.scope(moved) if moved else candidate

    def locate_input(self, path):
        candidate = Path(path).resolve()
        if not candidate.exists() and candidate.is_relative_to(self.directory):
            return self.locate(candidate)
        return candidate

    def read_json(self, path, *, legacy=None):
        candidate = self.locate(path)
        if legacy is not None and not candidate.exists():
            candidate = self.locate(legacy)
        return json.loads(candidate.read_text(encoding="utf-8"))
