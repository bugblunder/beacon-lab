"""Label-free features and causal, cumulative prefixes inside a fixed window."""
from __future__ import annotations

import statistics

NUMERIC_FEATURES = ("interval_cv", "request_size_cv")


def cv(values: list[float]) -> float | None:
    if len(values) < 2:
        return None
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean > 0 else None


def extract_prefixes(flows: list[dict], start_ts: float, end_ts: float, min_events=6) -> list[dict]:
    """Consume only completed observations available by each decision time."""
    usable = sorted(
        (row for row in flows if not row.get("error")
         and start_ts <= row["ts"] < end_ts
         and row["completed_ts"] <= end_ts
         and row["orig_bytes"] > 0 and row["resp_bytes"] > 0),
        key=lambda row: row["completed_ts"],
    )
    prefixes = []
    for length in range(min_events, len(usable) + 1):
        current = usable[:length]
        times = sorted(row["ts"] for row in current)
        intervals = [b - a for a, b in zip(times, times[1:])]
        prefixes.append({
            "n_events": length,
            "interval_cv": cv(intervals),
            "request_size_cv": cv([float(row["orig_bytes"]) for row in current]),
            "decision_ts": current[-1]["completed_ts"],
            "elapsed_seconds": max(0.0, current[-1]["completed_ts"] - start_ts),
        })
    return prefixes


def build_record(run: dict, flows: list[dict], min_events=6) -> dict:
    # Whitelist fields. Labels, profile names, seeds, payloads, IPs, ports, and
    # absolute start time are deliberately absent from the predictive features.
    observed = [row for row in flows if not row.get("error")
                and run["start_ts"] <= row["ts"] < run["end_ts"]
                and row["completed_ts"] <= run["end_ts"]]
    return {
        "run_id": run["run_id"],
        "transport": run["transport"],
        "observer": observed[0].get("observer", "unknown") if observed else "unknown",
        "prefixes": extract_prefixes(observed, run["start_ts"], run["end_ts"], min_events),
        "client_signals": [
            {"elapsed_seconds": max(0, row["completed_ts"] - run["start_ts"]),
             "user_agent": row.get("user_agent"), "ja3": row.get("ja3")}
            for row in sorted(observed, key=lambda x: x["completed_ts"])
        ],
        "observed_connections": len(observed),
        "min_events": min_events,
    }
