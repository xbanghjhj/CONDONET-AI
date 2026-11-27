import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from statistics import median

from lab.policy import load_cases, require
from scripts.evaluation import CSV_FIELDS, ROOT, TIMINGS, slots, write_json


def load_runs(paths, matrix):
    observations = []
    ids = set()
    for path in paths:
        with path.open(newline="", encoding="utf-8") as stream:
            csv_rows = csv.DictReader(stream)
            require(csv_rows.fieldnames == CSV_FIELDS, f"{path}: unexpected CSV header")
            for row in csv_rows:
                case = matrix.get(row["slot_id"])
                require(case is not None and (row["test_id"], row["ground_truth"]) == (case.id, case.truth),
                        f"{path}: scenario does not match slot {row['slot_id']}")
                run_id = row["run_id"]
                require(run_id and run_id not in ids, f"{path}: duplicate or missing run ID")
                directory = (ROOT / row["evidence"]).resolve()
                require(directory.is_relative_to(ROOT / "evidence") and directory.name == run_id,
                        f"{path}: evidence path does not match {run_id}")
                stored = json.loads((directory / "trial.json").read_text(encoding="utf-8"))
                normalized = {key: "" if stored["row"].get(key) is None else str(stored["row"][key])
                              for key in CSV_FIELDS}
                require(row == normalized, f"{path}: CSV and original evidence differ for {run_id}")
                for label, (first, last) in TIMINGS.items():
                    if value := row[f"{label}_seconds"]:
                        clocks = stored["monotonic_ns"]
                        require(float(value) == round((clocks[last] - clocks[first]) / 1e9, 3),
                                f"{path}: invalid monotonic interval for {run_id}")
                if row["action_id"]:
                    action = json.loads((directory / "action.json").read_text(encoding="utf-8"))
                    require(action["approval"]["id"] == row["action_id"] and
                            all(item["incident_id"] == row["incident_id"] for item in action["audit"]),
                            f"{path}: audit does not match {run_id}")
                require(row["verdict"] in {"PASS", "FAIL", "NOT RUN"}, f"{path}: invalid verdict")
                ids.add(run_id)
                observations.append(row)
    return observations


def timing(rows, key):
    samples = [float(row[key]) for row in rows if row.get(key)]
    return {"count": len(samples), "median": round(median(samples), 3) if samples else None,
            "max": max(samples, default=None)}


def summarize(rows, policy_rows, matrix, protection_verified, missing_reason):
    original = {}
    retries = []
    for row in rows:
        if row["slot_id"] in original:
            retries.append(row["run_id"])
        else:
            original[row["slot_id"]] = row
    primary = [original.get(slot, {"test_id": case.id, "slot_id": slot, "ground_truth": case.truth,
                                  "verdict": "NOT RUN", "reason": missing_reason})
               for slot, case in matrix.items()]
    service = [row for row in primary if row["test_id"] in {"01", "02"}]
    quarantine = [row for row in primary if row["test_id"] == "06"]
    applied = [row for row in primary if row.get("applied_at")]
    policy = Counter(row["status"] for row in policy_rows)
    detection = timing(service, "detection_seconds")
    trials = Counter(row["verdict"] for row in primary)
    diagnosis = sum(row.get("predicted_class") == row["ground_truth"] for row in primary)
    service_verified = sum(bool(row.get("verified_at")) and row["verdict"] == "PASS" for row in service)
    quarantine_verified = sum(bool(row.get("verified_at")) and row["verdict"] == "PASS" for row in quarantine)
    audit = sum(row.get("audit_complete") == "True" for row in applied)
    unapproved = sum(not row.get("approved_at") for row in applied)
    all_actions = [row for row in rows if row.get("applied_at")]
    successful_actions = [row for row in all_actions if row.get("verified_at") and row["verdict"] == "PASS"]
    observed_services = [row for row in rows if row["test_id"] in {"01", "02"}]
    expected_policy = len(load_cases())
    gate = {"policy_complete": policy == {"PASS": expected_policy},
            "24_trials_executed": trials["NOT RUN"] == 0,
            "service_detection": detection["count"] == 6 and detection["max"] <= 60,
            "classification": diagnosis >= 20, "rb01_rb02": service_verified == 6,
            "rb03": quarantine_verified == 3, "protected_changes": protection_verified and unapproved == 0,
            "audit_complete": len(applied) == 9 and audit == len(applied)}
    return {"planned": len(matrix), "original_verdicts": dict(trials), "retries": retries,
            "policy": {"pass": policy["PASS"], "planned": expected_policy},
            "classification": {"correct": diagnosis, "planned": len(matrix)},
            "rb01_rb02": {"verified": service_verified, "planned": 6},
            "rb03": {"verified": quarantine_verified, "planned": 3, "ttl_seconds": timing(quarantine, "ttl_seconds")},
            "audit": {"complete": audit, "applied_observed": len(applied), "planned": 9},
            "unauthorized_actions_in_observed_matrix": unapproved if applied else None,
            "observed_with_retries": {
                "attempts": len(rows),
                "pass_slots": len({row["slot_id"] for row in rows if row["verdict"] == "PASS"}),
                "verified_slots": sorted({row["slot_id"] for row in successful_actions}),
                "complete_audits": sum(row.get("audit_complete") == "True" for row in all_actions),
                "applied_actions": len(all_actions),
                "unauthorized_actions": sum(not row.get("approved_at") for row in all_actions) if all_actions else None,
                "service_detection_seconds": timing(observed_services, "detection_seconds"),
            },
            "timings_seconds": {key: timing(service if key == "detection" else primary, f"{key}_seconds")
                                for key in TIMINGS},
            "gates": gate, "day09_accepted": all(gate.values())}, primary


def main():
    parser = argparse.ArgumentParser(description="Recalculate the Day 9 results from original trial receipts.")
    parser.add_argument("--runs", action="append", type=Path, default=[],
                        help="Original batch CSVs followed by retry CSVs in execution order")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--protection-verified", action="store_true", help="Protection fixtures independently passed")
    parser.add_argument("--missing-reason", default="No original trial receipt")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    matrix = slots()
    runs = load_runs(args.runs, matrix)
    cases = load_cases()
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    policy_rows = [row for row in policy["checks"] if row["name"] in cases]
    require(len({row["name"] for row in policy_rows}) == len(policy_rows), "Duplicated policy case")
    summary, primary = summarize(runs, policy_rows, matrix, args.protection_verified, args.missing_reason)
    args.output.mkdir(parents=True, exist_ok=True)
    with (args.output / "runs.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(primary)
        original_ids = {row.get("run_id") for row in primary}
        writer.writerows(row for row in runs if row["run_id"] not in original_ids)
    write_json(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
