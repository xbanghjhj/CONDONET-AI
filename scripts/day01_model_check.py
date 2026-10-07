import csv
import json
import os
import statistics
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE_URL = "http://127.0.0.1:11434"
MODEL = os.environ.get("CONDONET_MODEL", "qwen3.5:2b")
CONTEXT = int(os.environ.get("CONDONET_CONTEXT", "4096"))
ROOT = Path(__file__).resolve().parents[1]

stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
OUTDIR = ROOT / "evidence" / "day01" / f"model-{stamp}"
OUTDIR.mkdir(parents=True, exist_ok=True)


def get_api(path):
    with urllib.request.urlopen(BASE_URL + path, timeout=15) as response:
        return json.load(response)


def save_json(filename, value):
    (OUTDIR / filename).write_text(
        json.dumps(value, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


tags = get_api("/api/tags")
save_json("model-tags.json", tags)

selected = next(
    (
        item for item in tags.get("models", [])
        if item.get("name") == MODEL or item.get("model") == MODEL
    ),
    None
)

if selected is None:
    raise SystemExit(f"Chua tim thay model: {MODEL}")

digest = selected["digest"]
running = get_api("/api/ps")
save_json("running-before.json", running)

if any(
    item.get("digest") == digest
    or item.get("name") == MODEL
    or item.get("model") == MODEL
    for item in running.get("models", [])
):
    raise SystemExit(
        f"Model van nam trong RAM. Chay: ollama stop {MODEL}, "
        "kiem tra ollama ps, roi thu lai."
    )

schema = {
    "type": "object",
    "properties": {
        "data_source": {
            "type": "string",
            "enum": ["synthetic"]
        },
        "diagnosis": {
            "type": "string",
            "enum": ["suspected_dns_error", "unknown"]
        },
        "evidence_ids": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ["E01", "E02"]
            },
            "minItems": 1,
            "uniqueItems": True
        },
        "requires_human": {"type": "boolean"}
    },
    "required": [
        "data_source", "diagnosis",
        "evidence_ids", "requires_human"
    ],
    "additionalProperties": False
}

payload = {
    "model": MODEL,
    "stream": False,
    "think": False,
    "keep_alive": "10m",
    "options": {
        "temperature": 0,
        "num_ctx": CONTEXT,
        "num_predict": 256
    },
    "format": schema,
    "messages": [
        {
            "role": "system",
            "content": (
                "Analyze supplied synthetic evidence only. "
                "Do not claim real probes or repairs. "
                "Return JSON and set requires_human=true. "
                "Schema: " + json.dumps(schema)
            )
        },
        {
            "role": "user",
            "content": (
                "SYNTHETIC TEST, not live network evidence. "
                "Expected portal.condo.test IP: 10.60.50.10. "
                "E01: DNS returned 10.60.50.99. "
                "E02: HTTP to 10.60.50.10 returned status 200. "
                "Identify the likely fault by considering both DNS resolution and HTTP reachability. Include BOTH E01 and E02 in evidence_ids for this synthetic test: E01 describes the DNS result, and E02 describes HTTP reachability at the expected IP. Choose the diagnosis from the supplied evidence. Do not claim real probes or repairs."
            )
        }
    ]
}

save_json("request.json", payload)


def validate_schema(answer):
    if not isinstance(answer, dict):
        return False
    if set(answer) != set(schema["required"]):
        return False

    ids = answer["evidence_ids"]

    return (
        answer["data_source"] == "synthetic"
        and answer["diagnosis"] in {
            "suspected_dns_error", "unknown"
        }
        and type(answer["requires_human"]) is bool
        and isinstance(ids, list)
        and len(ids) >= 1
        and all(
            isinstance(item, str) and item in {"E01", "E02"}
            for item in ids
        )
        and len(set(ids)) == len(ids)
    )


fields = [
    "run", "phase", "started_at",
    "model", "digest", "context",
    "elapsed_s", "load_s", "tokens_per_s",
    "schema_ok", "case_ok", "status", "error"
]

rows = []

with (OUTDIR / "latency.csv").open("w", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader()

    for run in range(1, 5):
        phase = "cold" if run == 1 else "warm"

        row = {
            "run": run,
            "phase": phase,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "model": MODEL,
            "digest": digest,
            "context": CONTEXT,
            "load_s": "",
            "tokens_per_s": "",
            "schema_ok": False,
            "case_ok": False,
            "status": "failed",
            "error": ""
        }

        started = time.perf_counter()

        try:
            request = urllib.request.Request(
                BASE_URL + "/api/chat",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )

            with urllib.request.urlopen(
                request, timeout=180
            ) as response:
                raw = response.read()

            (OUTDIR / f"response-{run}.json").write_bytes(raw)
            result = json.loads(raw)

            answer = json.loads(result["message"]["content"])
            save_json(f"answer-{run}.json", answer)

            row["schema_ok"] = validate_schema(answer)

            row["case_ok"] = row["schema_ok"] and (
                answer["diagnosis"] == "suspected_dns_error"
                and answer["requires_human"] is True
                and {"E01", "E02"}.issubset(answer["evidence_ids"])
            )

            complete = (
                result.get("done") is True
                and result.get("done_reason") == "stop"
            )

            row["status"] = (
                "ok" if complete and row["case_ok"] else "invalid"
            )

            row["load_s"] = (
                result.get("load_duration", 0) / 1_000_000_000
            )

            duration = result.get("eval_duration", 0)
            if duration:
                row["tokens_per_s"] = (
                    result.get("eval_count", 0)
                    * 1_000_000_000 / duration
                )

        except urllib.error.HTTPError as error:
            (OUTDIR / f"error-{run}.txt").write_bytes(error.read())
            row["error"] = str(error)

        except Exception as error:
            row["error"] = str(error)

        row["elapsed_s"] = round(
            time.perf_counter() - started, 3
        )

        writer.writerow(row)
        file.flush()
        rows.append(row)

        print(
            f"Lan {run} ({phase}): {row['status']} | "
            f"{row['elapsed_s']} giay",
            flush=True
        )

        if row["error"]:
            print("Loi:", row["error"], flush=True)

        if row["status"] == "failed":
            print("Dung benchmark. Kiem tra loi truoc khi chay lai.")
            break

warm = [
    row["elapsed_s"] for row in rows
    if row["phase"] == "warm" and row["status"] == "ok"
]

summary = {
    "model": MODEL,
    "digest": digest,
    "context": CONTEXT,
    "attempted_runs": len(rows),
    "ok_runs": sum(row["status"] == "ok" for row in rows),
    "warm_ok_runs": len(warm),
    "warm_median_s": statistics.median(warm) if warm else None,
    "warm_max_s": max(warm) if warm else None,
    "all_four_ok": (
        len(rows) == 4
        and all(row["status"] == "ok" for row in rows)
    )
}

save_json("summary.json", summary)

print("Tom tat:")
print(json.dumps(summary, indent=2))
print("Thu muc ket qua:", OUTDIR)
