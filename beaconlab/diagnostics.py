"""Read-only experiment audit and development-only sensitivity analysis.

Ground-truth profile names are joined after predictions solely for diagnosis.
Nothing in this module mutates a model or chooses a policy from held-out data.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
from pathlib import Path
import statistics

from .evaluation import evaluate
from .models import predict, select_combined
from .report import DISPLAY, create_report, number, pct
from .storage import read_json, read_jsonl, write_csv, write_json, write_jsonl


def development_sensitivity(manifest: dict, records: list[dict]) -> list[dict]:
    development = [row for row in manifest["runs"]
                   if row["split"] == "development" and row["status"] == "complete"]
    by_id = {row["run_id"]: row for row in records}
    rows = []
    for transport in sorted({row["transport"] for row in development}):
        subset = [row for row in development if row["transport"] == transport]
        for minimum in (6, 10, 14):
            for persistence in (1, 3):
                result = {"split": "development", "transport": transport,
                          "min_events": minimum, "consecutive_prefixes": persistence}
                if minimum < manifest["config"]["min_events"]:
                    rows.append({**result, "status": "prefixes_not_retained"})
                    continue
                try:
                    rule = select_combined(subset, by_id, min_events=minimum,
                                           consecutive_prefixes=persistence)
                except ValueError as exc:
                    rows.append({**result, "status": str(exc)})
                    continue
                outcomes = [predict(by_id[row["run_id"]], rule) for row in subset if row["label"] == 1]
                benign_outcomes = [predict(by_id[row["run_id"]], rule) for row in subset if row["label"] == 0]
                delays = [row["detection_seconds"] for row in outcomes if row["prediction"] is True]
                rows.append({**result, "status": rule["selection_status"],
                             "interval_cv_max": rule["interval_cv_max"],
                             "request_size_cv_max": rule["request_size_cv_max"],
                             **{key: rule["development"][key] for key in (
                                 "tp", "fn", "fp", "tn", "tpr", "fpr", "coverage")},
                             "positive_coverage": sum(row["available"] for row in outcomes) / len(outcomes),
                             "benign_coverage": sum(row["available"] for row in benign_outcomes) / len(benign_outcomes),
                             "median_detection_seconds": statistics.median(delays) if delays else None})
    return rows


def feature_plot(output: Path, runs: list[dict], by_id: dict) -> bool:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return False
    transports = sorted({row["transport"] for row in runs})
    styles = {"channel_regular": ("#bd5a22", "o"), "channel_variable": ("#bd5a22", "^"),
              "health_check": ("#20785a", "s"), "monitor_heartbeat": ("#376daf", "D"),
              "update_check": ("#88669e", "v")}
    fig, axes = plt.subplots(1, len(transports), figsize=(5.5 * len(transports), 4.7),
                             squeeze=False, sharex=True, sharey=True, layout="constrained")
    for axis, transport in zip(axes[0], transports):
        for profile in sorted({row["profile"] for row in runs}):
            points = [by_id[row["run_id"]]["prefixes"][-1] for row in runs
                      if row["transport"] == transport and row["profile"] == profile
                      and by_id[row["run_id"]]["prefixes"]]
            color, marker = styles.get(profile, ("#555555", "o"))
            axis.scatter([p["interval_cv"] for p in points], [p["request_size_cv"] for p in points],
                         color=color, marker=marker, alpha=.65, s=32, label=profile.replace("_", " "))
        axis.set_xscale("log")
        axis.set_yscale("log")
        axis.set_xlabel("Timing CV (log scale)")
        axis.set_ylabel("Originator-byte CV (log scale)")
        axis.tick_params(axis="y", labelleft=True)
        axis.set_title(transport.upper(), loc="left", fontweight="bold")
        axis.grid(alpha=.2)
        axis.legend(fontsize=7, frameon=False, loc="best")
    fig.suptitle("Held-out final-prefix features · illustrative only; alerts use causal prefix histories", fontsize=10)
    folder = output / "figures"
    folder.mkdir(exist_ok=True)
    fig.savefig(folder / "feature_overlap.png", dpi=180)
    fig.savefig(folder / "feature_overlap.svg")
    plt.close(fig)
    return True


def _local_rule(rule: dict, record: dict) -> dict:
    return rule["transport_rules"].get(record["transport"], {}) if rule["kind"] == "by_transport" else rule


def audit_experiment(run_dir: Path, output: Path, *, charts=True):
    run_dir, output = run_dir.resolve(), output.resolve()
    if output == run_dir or output in run_dir.parents:
        raise ValueError("Audit output must not replace the experiment or its parent")
    if output.exists():
        raise ValueError("Audit output already exists; choose a new directory")
    # The standard evaluator checks model integrity and split overlap first.
    manifest, model, summary = evaluate(run_dir, output=output)
    create_report(output, manifest, model, summary, charts=charts)
    records = read_jsonl(run_dir / "features.jsonl")
    by_id = {row["run_id"]: row for row in records}
    development = [row for row in manifest["runs"]
                   if row["split"] == "development" and row["status"] == "complete"]
    held_out = [row for row in manifest["runs"] if row["split"] == "test" and row["status"] == "complete"]
    cases, alerts, feature_groups = [], [], defaultdict(list)
    for run in manifest["runs"]:
        if run["status"] != "complete":
            continue
        record = by_id[run["run_id"]]
        prefixes = record["prefixes"]
        flows = read_jsonl(run_dir / "observations" / (run["run_id"] + ".jsonl"))
        usable = [row for row in flows if not row.get("error")
                  and run["start_ts"] <= row["ts"] < run["end_ts"]
                  and row["completed_ts"] <= run["end_ts"] and row["orig_bytes"] > 0]
        if prefixes:
            feature_groups[(run["split"], run["transport"], run["profile"])].append({
                **prefixes[-1], "mean_orig_bytes": statistics.fmean(row["orig_bytes"] for row in usable)})
        if run["split"] != "test":
            continue
        for name, rule in model["rules"].items():
            outcome = predict(record, rule)
            if outcome["prediction"] is not True:
                continue
            selected = _local_rule(rule, record)
            prefix = next((row for row in prefixes
                           if row["elapsed_seconds"] == outcome["detection_seconds"]), {})
            event = {
                "event_type": "beaconlab.client_novelty" if selected.get("kind") == "client_novelty" else "beaconlab.periodic_traffic_candidate",
                "run_id": run["run_id"], "detector": name, "transport": run["transport"],
                "observer": record["observer"], "synthetic_lab": True,
                "detection_seconds": outcome["detection_seconds"],
                "evidence": {key: prefix.get(key) for key in ("n_events", "interval_cv", "request_size_cv")},
                "rule": {key: selected[key] for key in (
                    "kind", "interval_cv_max", "request_size_cv_max", "min_events", "consecutive_prefixes") if key in selected},
                "interpretation": "Investigation lead only; this event does not establish malicious intent",
            }
            alerts.append(event)
            if run["label"] == 0:
                final_matches = None
                if prefixes and selected.get("kind") in {"timing", "timing_and_size"}:
                    final = prefixes[-1]
                    final_matches = final["interval_cv"] <= selected["interval_cv_max"]
                    if selected["kind"] == "timing_and_size":
                        final_matches = final_matches and final["request_size_cv"] <= selected["request_size_cv_max"]
                cases.append({"run_id": run["run_id"], "detector": name,
                              "transport": run["transport"], "profile": run["profile"],
                              "detection_seconds": outcome["detection_seconds"],
                              **event["evidence"],
                              "interval_cv_max": selected.get("interval_cv_max"),
                              "request_size_cv_max": selected.get("request_size_cv_max"),
                              "final_prefix_still_matches": final_matches})
    distributions = []
    for (split, transport, profile), values in sorted(feature_groups.items()):
        row = {"split": split, "transport": transport, "profile": profile, "n_runs": len(values)}
        for feature in ("interval_cv", "request_size_cv", "mean_orig_bytes"):
            observed = [v[feature] for v in values if v.get(feature) is not None]
            for name, func in (("min", min), ("median", statistics.median), ("max", max)):
                row[feature + "_" + name] = func(observed) if observed else None
        distributions.append(row)
    sensitivity = development_sensitivity(manifest, records)
    source_hashes = {name: hashlib.sha256((run_dir / name).read_bytes()).hexdigest()
                     for name in ("manifest.json", "model.json", "features.jsonl")}
    audit = {
        "kind": "retrospective_diagnostic_audit", "source_experiment": run_dir.name,
        "source_sha256": source_hashes,
        "held_out_rules": "Existing frozen models only; no refitting for held-out diagnosis",
        "sensitivity_scope": "Development data only; no primary-policy selection or validation claim",
        "sensitivity_training_run_ids": [row["run_id"] for row in development],
        "n_held_out": len(held_out), "false_positive_cases": cases,
        "feature_distributions": distributions, "development_sensitivity": sensitivity,
        "paired_comparisons": summary.get("paired_comparisons", []),
    }
    write_json(output / "audit.json", audit)
    write_jsonl(output / "alerts.jsonl", alerts)
    write_csv(output / "false_positive_cases.csv", cases, ["run_id", "detector", "transport", "profile",
        "detection_seconds", "n_events", "interval_cv", "request_size_cv", "interval_cv_max",
        "request_size_cv_max", "final_prefix_still_matches"])
    write_csv(output / "feature_distributions.csv", distributions)
    write_csv(output / "development_sensitivity.csv", sensitivity, ["split", "transport", "min_events",
        "consecutive_prefixes", "status", "interval_cv_max", "request_size_cv_max", "tp", "fn",
        "fp", "tn", "tpr", "fpr", "coverage", "positive_coverage", "benign_coverage", "median_detection_seconds"])
    plotted = feature_plot(output, held_out, by_id) if charts else False
    lines = ["# BeaconLab baseline and refinement audit", "",
             "This is a retrospective diagnosis of saved observations. The original source files and frozen models are unchanged.", "",
             "## Where false alerts occur", "",
             "| Detector | Transport | Benign workload | False alerts / scored benign runs |",
             "|---|---|---|---:|"]
    for row in summary["profile_groups"]:
        if row["fp"] + row["tn"]:
            lines.append(f"| {DISPLAY[row['detector']]} | {row['transport']} | {row['profile']} | {row['fp']}/{row['fp'] + row['tn']} |")
    lines += ["", "## Measurement-scale diagnosis", "",
              "Connection byte counts include protocol overhead. CV = standard deviation / mean, so adding roughly constant bytes reduces CV. HTTP and HTTPS thresholds therefore need explicit evaluation; these observational differences do not isolate a causal effect of TLS.", "",
              "| Held-out workload | Transport | Median timing CV | Median size CV | Median mean originator bytes |",
              "|---|---|---:|---:|---:|"]
    for row in distributions:
        if row["split"] == "test":
            lines.append(f"| {row['profile']} | {row['transport']} | {row['interval_cv_median']:.4f} | {row['request_size_cv_median']:.4f} | {row['mean_orig_bytes_median']:.1f} |")
    if plotted:
        lines += ["", "![Held-out feature distributions](figures/feature_overlap.png)", ""]
    lines += ["", "## Development-only gate sensitivity", "",
              "Each cell refits the same fixed grid on development runs only. These are in-sample diagnostics; they must not be reported as held-out performance or used to retrospectively select a winning test result. Missing cells mean inadequate available evidence.", "",
              "Raising the minimum can exclude slow benign clients entirely. A lower conditional FPR with lower benign coverage does not establish better detection.", "",
              "| Transport | Minimum events | Consecutive prefixes | Dev TPR | Dev FPR | Positive coverage | Benign coverage | Median delay (s) |",
              "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for row in sensitivity:
        lines.append(f"| {row['transport']} | {row['min_events']} | {row['consecutive_prefixes']} | "
                     f"{pct(row.get('tpr'))} | {pct(row.get('fpr'))} | {pct(row.get('positive_coverage'))} | {pct(row.get('benign_coverage'))} | {number(row.get('median_detection_seconds'))} |")
    transient = sum(row["final_prefix_still_matches"] is False for row in cases if row["detector"] == "timing_and_size")
    lines += ["", "## How to read this evidence", "",
              f"- {transient} pooled timing-plus-size false alerts no longer matched at the final prefix. They still count as false alerts; later data cannot erase an emitted alert.",
              "- Consecutive cumulative prefixes overlap. Persistence can suppress transient triggers but is not independent confirmation or a solution to sustained benign periodicity.",
              "- `false_positive_cases.csv` traces each benign alert to the exact threshold and causal prefix.",
              "- `alerts.jsonl` provides structured, label-free evidence for a future SIEM adapter. No SIEM ingestion has been performed.",
              "- Class/profile information is joined only for evaluation. It is not an input to prediction.",
              "- Review RESULTS.md/report.html for held-out metrics, uncertainty, paired changes and conclusions.", ""]
    (output / "AUDIT.md").write_text("\n".join(lines), encoding="utf-8")
    # Confirm the diagnostic operation did not modify any original source data.
    for name, original in source_hashes.items():
        if hashlib.sha256((run_dir / name).read_bytes()).hexdigest() != original:
            raise RuntimeError("Audit source changed during execution")
    return audit
