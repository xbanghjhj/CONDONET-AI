from pathlib import Path

import pytest

from scripts.evidence_store import ACTION_AUDIT, EvidenceStore, write_json


def test_reads_current_and_historical_audit_without_rewriting_receipts(tmp_path):
    store = EvidenceStore(tmp_path)
    legacy = Path("evidence/day09/original/trials/r1-01-run")
    current = Path("evidence/evaluation/original/r1-01-run")
    store.scope(current).mkdir(parents=True)
    receipt = {"row": {"evidence": str(legacy)}}
    write_json(store.scope(current / "trial.json"), receipt)
    write_json(store.scope(current / ACTION_AUDIT), {"audit": ["verified"]})
    write_json(store.directory / "migration-manifest.json", {"files": [
        {"old": str(legacy / "trial.json"), "new": str(current / "trial.json")},
        {"old": str(legacy / "action.json"), "new": str(current / ACTION_AUDIT)},
    ]})

    assert store.read_json(current / "trial.json") == receipt
    assert store.read_json(legacy / "trial.json") == receipt
    assert store.read_json(legacy / ACTION_AUDIT, legacy=legacy / "action.json") == {"audit": ["verified"]}


def test_reads_unmigrated_audit_without_manifest(tmp_path):
    store = EvidenceStore(tmp_path)
    directory = store.scope("evidence/legacy")
    directory.mkdir(parents=True)
    write_json(directory / "action.json", {"audit": []})

    assert store.read_json(directory / ACTION_AUDIT, legacy=directory / "action.json") == {"audit": []}


def test_refuses_paths_outside_evidence_even_through_archive(tmp_path):
    store = EvidenceStore(tmp_path)
    store.directory.mkdir()
    old = "evidence/day09/receipt.json"
    write_json(store.directory / "migration-manifest.json", {"files": [
        {"old": old, "new": "evidence/../receipt.json"},
    ]})

    with pytest.raises(ValueError, match="outside"):
        store.locate(old)
    with pytest.raises(ValueError, match="outside"):
        store.scope("evidence/../../receipt.json")
