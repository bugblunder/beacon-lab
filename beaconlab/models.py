"""Small preregistered rule families, fitted ONLY on development runs."""
from __future__ import annotations

import math

from .features import NUMERIC_FEATURES
from .metrics import summarize

CV_GRID = (0.0, 0.03, 0.06, 0.10, 0.20, 0.35, 0.50, 0.80, 1.20)
SIZE_GRID = (0.0, 0.01, 0.03, 0.06, 0.10, 0.20, 0.40, 0.80)


def predict(record: dict, rule: dict) -> dict:
    kind = rule["kind"]
    if kind == "by_transport":
        selected = rule["transport_rules"].get(record["transport"])
        if selected is None:
            return {"prediction": None, "available": False, "detection_seconds": None}
        return predict(record, selected)
    if kind == "client_novelty":
        field = "ja3" if record["transport"] == "https" else "user_agent"
        known = set(rule["known_benign"][field])
        signals = [row for row in record["client_signals"] if row.get(field)]
        if not signals or not known:
            return {"prediction": None, "available": False, "detection_seconds": None}
        for signal in signals:
            if signal[field] not in known:
                return {"prediction": True, "available": True,
                        "detection_seconds": signal["elapsed_seconds"]}
        return {"prediction": False, "available": True, "detection_seconds": None}
    if kind not in {"never_alert", "timing", "timing_and_size"}:
        raise ValueError(f"Unknown rule kind: {kind}")
    eligible = [row for row in record["prefixes"]
                if row.get("n_events", 0) >= rule.get("min_events", 0)]
    valid = [row for row in eligible if all(
        isinstance(row.get(key), (int, float)) and math.isfinite(row[key])
        for key in NUMERIC_FEATURES)]
    if not valid:
        return {"prediction": None, "available": False, "detection_seconds": None}
    if kind == "never_alert":
        return {"prediction": False, "available": True, "detection_seconds": None}
    required = rule.get("consecutive_prefixes", 1)
    # A short window cannot be scored as a negative just because it lacks the
    # observations required by a persistence policy.
    longest = length = 0
    for prefix in eligible:
        length = length + 1 if all(isinstance(prefix.get(key), (int, float))
            and math.isfinite(prefix[key]) for key in NUMERIC_FEATURES) else 0
        longest = max(longest, length)
    if longest < required:
        return {"prediction": None, "available": False, "detection_seconds": None}
    streak = 0
    for prefix in eligible:
        if not all(isinstance(prefix.get(key), (int, float)) and math.isfinite(prefix[key])
                   for key in NUMERIC_FEATURES):
            streak = 0
            continue
        matched = prefix["interval_cv"] <= rule["interval_cv_max"]
        if kind == "timing_and_size":
            matched = matched and prefix["request_size_cv"] <= rule["request_size_cv_max"]
        streak = streak + 1 if matched else 0
        if streak >= required:
            return {"prediction": True, "available": True,
                    "detection_seconds": prefix["elapsed_seconds"]}
    return {"prediction": False, "available": True, "detection_seconds": None}


def fit(manifest: dict, records: list[dict]) -> dict:
    by_id = {record["run_id"]: record for record in records}
    development = [run for run in manifest["runs"]
                   if run["split"] == "development" and run["status"] == "complete"]
    if not development or {row["label"] for row in development} != {0, 1}:
        raise ValueError("Development data needs both traffic classes")
    if len({row["run_id"] for row in manifest["runs"]}) != len(manifest["runs"]):
        raise ValueError("Duplicate run IDs")
    if any(run["run_id"] not in by_id for run in development):
        raise ValueError("Missing development observations")

    def objective(rule):
        counts = {0: [0, 0], 1: [0, 0]}
        for run in development:
            outcome = predict(by_id[run["run_id"]], rule)
            if not outcome["available"]:
                continue
            label = run["label"]
            counts[label][1] += 1
            counts[label][0] += int(outcome["prediction"])
        if not counts[0][1] or not counts[1][1]:
            raise ValueError("Both development classes need enough observable connections")
        fpr = counts[0][0] / counts[0][1]
        tpr = counts[1][0] / counts[1][1]
        return ((tpr + 1 - fpr) / 2, -fpr)

    rules = {}
    for name in ("timing", "timing_and_size"):
        best_rule = {"kind": "never_alert"}
        best_score = objective(best_rule)
        for interval in CV_GRID:
            for size in (SIZE_GRID if name == "timing_and_size" else (None,)):
                candidate = {"kind": name, "interval_cv_max": interval}
                if size is not None:
                    candidate["request_size_cv_max"] = size
                score = objective(candidate)
                if score > best_score:
                    best_rule, best_score = candidate, score
        rules[name] = {**best_rule, "development_balanced_accuracy": best_score[0],
                       "development_fpr": -best_score[1]}
    known = {"ja3": set(), "user_agent": set()}
    for run in development:
        if run["label"] == 0:
            for signal in by_id[run["run_id"]]["client_signals"]:
                for field in known:
                    if signal.get(field):
                        known[field].add(signal[field])
    rules["client_novelty"] = {"kind": "client_novelty",
                             "known_benign": {key: sorted(values) for key, values in known.items()}}
    model = {
        "schema_version": 1,
        "training_run_ids": [run["run_id"] for run in development],
        "training_split": "development",
        "selection": "maximize development balanced accuracy; ties prefer lower FPR; never-alert fallback",
        "evaluation_policy": "first qualifying causal prefix; at most one alert per run",
        "numeric_feature_allowlist": list(NUMERIC_FEATURES),
        "grid": {"interval_cv_max": list(CV_GRID), "request_size_cv_max": list(SIZE_GRID)},
        "rules": rules,
    }
    if manifest.get("config", {}).get("refinement"):
        add_refinements(model, manifest, records)
    return model


def select_combined(development: list[dict], by_id: dict, *, min_events: int,
                    consecutive_prefixes: int, max_fpr: float | None = None) -> dict:
    """Fit one transport using development data and a fixed candidate grid.

    A development FPR cap is an empirical selection constraint, not a statistical
    guarantee. The no-alert policy is explicit and may have zero utility.
    """
    if {row["label"] for row in development} != {0, 1}:
        raise ValueError("Each transport needs both development classes")
    if any(row["split"] != "development" for row in development):
        raise ValueError("Selection accepts development runs only")
    settings = {"min_events": min_events, "consecutive_prefixes": consecutive_prefixes}

    def assess(rule):
        rows = [{"label": run["label"], "window_seconds": run.get("window_seconds", 1),
                 **predict(by_id[run["run_id"]], rule)} for run in development]
        return summarize(rows)

    # Use an ordinary impossible threshold rule for fallback so its coverage
    # requirement is identical to every candidate (including persistence).
    best_rule = {"kind": "timing_and_size", "interval_cv_max": -1.0,
                 "request_size_cv_max": -1.0, **settings}
    best = assess(best_rule)
    if best["tpr"] is None or best["fpr"] is None:
        raise ValueError("Insufficient observations for the refinement policy")

    def score(stats):
        return ((stats["tpr"] if max_fpr is not None else
                 (stats["tpr"] + 1 - stats["fpr"]) / 2), -stats["fpr"])

    for interval in CV_GRID:
        for size in SIZE_GRID:
            candidate = {"kind": "timing_and_size", "interval_cv_max": interval,
                         "request_size_cv_max": size, **settings}
            stats = assess(candidate)
            if max_fpr is not None and stats["fpr"] > max_fpr:
                continue
            if score(stats) > score(best):
                best_rule, best = candidate, stats
    return {**best_rule,
            "selection_status": "selected" if best["tp"] else "no_useful_development_rule",
            "development": {key: best[key] for key in (
                "tp", "fn", "fp", "tn", "tpr", "fpr", "coverage", "fpr_ci95")},
            "max_development_fpr": max_fpr}


def add_refinements(model: dict, manifest: dict, records: list[dict]):
    config = manifest["config"]["refinement"]
    by_id = {record["run_id"]: record for record in records}
    development = [run for run in manifest["runs"]
                   if run["split"] == "development" and run["status"] == "complete"]
    transports = sorted({run["transport"] for run in development})
    # Ablations isolate transport calibration from the persistence/minimum-event
    # change. All are frozen together before the same held-out collection.
    policies = (
        ("transport_calibrated", manifest["config"]["min_events"], 1, None),
        ("persistent_calibrated", config["min_events"], config["consecutive_prefixes"], None),
        ("budgeted_persistent", config["min_events"], config["consecutive_prefixes"],
         config["max_development_fpr"]),
    )
    for name, minimum, persistence, budget in policies:
        model["rules"][name] = {
            "kind": "by_transport",
            "transport_rules": {transport: select_combined(
                [run for run in development if run["transport"] == transport], by_id,
                min_events=minimum, consecutive_prefixes=persistence, max_fpr=budget)
                for transport in transports},
        }
    model["refinement"] = {
        **config,
        "primary_comparison": "timing_and_size versus persistent_calibrated on the same held-out runs",
        "budget_interpretation": "Empirical development cap, not a guaranteed held-out or operational FPR",
        "feature_scope": "Same two CV features; transport selects thresholds; no profile/label/seed at prediction",
        "ablation": "transport_calibrated isolates transport-specific fitting; persistent_calibrated also changes the event gate",
    }
