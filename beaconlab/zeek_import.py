"""Convert actual Zeek JSON logs into the same label-free observation format."""
from __future__ import annotations

from pathlib import Path

from .features import build_record
from .storage import read_json, read_jsonl, write_json, write_jsonl


def import_logs(log_directory: Path, run_directory: Path, output: Path):
    manifest = read_json(run_directory / "manifest.json")
    conn = read_jsonl(log_directory / "conn.log")
    http_rows = read_jsonl(log_directory / "http.log") if (log_directory / "http.log").exists() else []
    ssl_rows = read_jsonl(log_directory / "ssl.log") if (log_directory / "ssl.log").exists() else []
    http = {row["uid"]: row for row in http_rows}
    tls = {row["uid"]: row for row in ssl_rows}
    by_run = {run["run_id"]: [] for run in manifest["runs"]}
    unmatched = invalid = matched = 0
    for row in conn:
        try:
            ts = float(row["ts"])
            port = int(row["id.resp_p"])
            duration = float(row.get("duration", 0))
            orig, resp = float(row["orig_bytes"]), float(row["resp_bytes"])
        except (KeyError, ValueError, TypeError):
            invalid += 1
            continue
        candidates = [run for run in manifest["runs"]
                      if run["observer_port"] == port and run["start_ts"] <= ts < run["end_ts"]]
        if len(candidates) != 1:
            unmatched += 1
            continue
        run = candidates[0]
        ssl_row = tls.get(row["uid"], {})
        record = {
            "run_id": run["run_id"], "ts": ts, "completed_ts": ts + duration,
            "duration": duration, "orig_bytes": orig, "resp_bytes": resp,
            "transport": run["transport"], "observer": "zeek_pcap",
            "user_agent": http.get(row["uid"], {}).get("user_agent") if run["transport"] == "http" else None,
            "ja3": ssl_row.get("ja3"), "ja3_string": None,
            "error": "missed_capture_bytes" if row.get("missed_bytes", 0) else None,
        }
        by_run[run["run_id"]].append(record)
        matched += 1
    if not matched:
        raise ValueError("No Zeek connections matched the manifest's windows and observer ports")
    output.mkdir(parents=True, exist_ok=False)
    records = []
    for run in manifest["runs"]:
        flows = by_run[run["run_id"]]
        write_jsonl(output / "observations" / (run["run_id"] + ".jsonl"), flows)
        records.append(build_record(run, flows, manifest["config"]["min_events"]))
    write_jsonl(output / "features.jsonl", records)
    report = {"matched_connections": matched, "unmatched_connections": unmatched,
              "invalid_connections": invalid, "observer": "zeek_pcap",
              "ja3_available": any(row.get("ja3") for flows in by_run.values() for row in flows),
              "note": "JA3 requires a compatible Zeek fingerprinting package; missing fields remain unavailable."}
    write_json(output / "import_report.json", report)
    return report
