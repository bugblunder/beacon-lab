from __future__ import annotations

from pathlib import Path
import hashlib

from .metrics import summarize
from .models import predict
from .storage import read_json, read_jsonl, write_csv, write_json


def evaluate(run_dir: Path, *, feature_file: Path | None = None, model_file: Path | None = None,
             output: Path | None = None):
    manifest = read_json(run_dir / "manifest.json")
    model = read_json(model_file or run_dir / "model.json")
    features = read_jsonl(feature_file or run_dir / "features.jsonl")
    if len({row["run_id"] for row in features}) != len(features):
        raise ValueError("Duplicate feature run IDs")
    by_id = {row["run_id"]: row for row in features}
    test = [row for row in manifest["runs"] if row["split"] == "test" and row["status"] == "complete"]
    if not test:
        raise ValueError("No complete held-out runs")
    if set(model["training_run_ids"]) & {row["run_id"] for row in test}:
        raise ValueError("Leakage: model training IDs overlap the held-out test set")
    if len({row["run_id"] for row in manifest["runs"]}) != len(manifest["runs"]):
        raise ValueError("Duplicate manifest run IDs")
    if model_file is None and manifest.get("model_sha256"):
        if hashlib.sha256((run_dir / "model.json").read_bytes()).hexdigest() != manifest["model_sha256"]:
            raise ValueError("Frozen model hash mismatch; use the originally recorded model")
    if any(row["run_id"] not in by_id for row in test):
        raise ValueError("Missing held-out observations")
    predictions = []
    for run in test:
        for name, rule in model["rules"].items():
            predictions.append({
                "run_id": run["run_id"], "detector": name, "transport": run["transport"],
                "profile": run["profile"], "label": run["label"],
                "window_seconds": run["window_seconds"],
                **predict(by_id[run["run_id"]], rule),
            })
    groups = []
    for name in model["rules"]:
        for transport in ["all"] + sorted({row["transport"] for row in test}):
            rows = [row for row in predictions if row["detector"] == name
                    and (transport == "all" or row["transport"] == transport)]
            groups.append({"detector": name, "transport": transport, **summarize(rows)})
    profile_groups = []
    for name in model["rules"]:
        for transport in sorted({row["transport"] for row in test}):
            for profile in sorted({row["profile"] for row in test}):
                rows = [row for row in predictions if row["detector"] == name
                        and row["transport"] == transport and row["profile"] == profile]
                profile_groups.append({"detector": name, "transport": transport,
                                       "profile": profile, **summarize(rows)})
    summary = {
        "schema_version": 1, "evaluation_split": "test",
        "unit": "one fixed-duration client-destination run; alert at first qualifying causal prefix",
        "observer": sorted({by_id[run["run_id"]]["observer"] for run in test}),
        "n_development": len(model["training_run_ids"]), "n_test": len(test),
        "failed_runs_excluded": sum(row["status"] != "complete" for row in manifest["runs"]),
        "groups": groups, "profile_groups": profile_groups,
        "notes": [
            "Labels describe synthetic workload purpose, not observed malicious intent.",
            "Reported rates are conditional on detector availability; coverage is reported separately.",
            "Wilson intervals are approximate per-run binomial intervals, not guarantees of real-network generalization.",
            "Prevalence-adjusted precision is hypothetical and assumes measured TPR/FPR transfer unchanged.",
            "Benign-hour alert rates from accelerated pilot traffic are not production alert-volume forecasts.",
            "The first qualifying prefix emits at most one alert per run; thresholds remain frozen.",
            "Original baselines use the configured minimum-event gate. Refinement policies, when present, carry explicit gates and persistence; client novelty does not use them.",
            "Client novelty means an observed UA/JA3 was absent from benign development signals; it can flag legitimate population changes and does not establish maliciousness.",
            "Repeated config/seed inputs are deterministic only with fixed generator code/runtime; measured traffic, fitted rules, and results may vary between live executions.",
        ],
    }
    if model.get("refinement"):
        summary["refinement"] = model["refinement"]
        summary["notes"] += [
            "Transport calibration and persistence were chosen after reviewing the earlier pilot, then evaluated on fresh runs. This remains the same synthetic generator family.",
            "The false-positive budget constrains development observations only. Report held-out misses and uncertainty even when no alerts occur.",
            "Consecutive cumulative prefixes overlap; persistence is a debounce policy, not independent statistical confirmation.",
        ]
    summary["paired_comparisons"] = []
    for candidate in ("transport_calibrated", "persistent_calibrated", "budgeted_persistent"):
        if candidate not in model["rules"]:
            continue
        reference = {row["run_id"]: row for row in predictions if row["detector"] == "timing_and_size"}
        other = {row["run_id"]: row for row in predictions if row["detector"] == candidate}
        pairs = [(reference[key], other[key]) for key in reference
                 if reference[key]["available"] and other[key]["available"]]
        summary["paired_comparisons"].append({
            "reference": "timing_and_size", "candidate": candidate, "n_jointly_scored": len(pairs),
            "benign_alerts_removed": sum(a["label"] == 0 and a["prediction"] and not b["prediction"] for a, b in pairs),
            "benign_alerts_added": sum(a["label"] == 0 and not a["prediction"] and b["prediction"] for a, b in pairs),
            "positive_detections_lost": sum(a["label"] == 1 and a["prediction"] and not b["prediction"] for a, b in pairs),
            "positive_detections_gained": sum(a["label"] == 1 and not a["prediction"] and b["prediction"] for a, b in pairs),
        })
    output = output or run_dir
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "metrics.json", summary)
    write_csv(output / "predictions.csv", predictions)
    write_csv(output / "metrics.csv", groups, [
        "detector", "transport", "n_total", "n_scored", "unscored", "coverage",
        "tp", "fn", "fp", "tn", "tpr", "fpr", "precision",
        "false_alerts_per_benign_client_hour", "median_detection_seconds",
    ])
    return manifest, model, summary
