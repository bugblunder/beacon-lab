"""Confusion counts, uncertainty, and explicitly hypothetical prevalence scenarios."""
from __future__ import annotations

import math
import statistics


def wilson(successes: int, total: int, z=1.959963984540054) -> list[float] | None:
    if total <= 0:
        return None
    p = successes / total
    denom = 1 + z * z / total
    middle = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    # Floating-point roundoff at p=0 or p=1 must not put the point estimate
    # outside its own interval (or create a negative plotting error bar).
    return [min(p, max(0.0, middle - half)), max(p, min(1.0, middle + half))]


def adjusted_precision(tpr: float | None, fpr: float | None, prevalence: float) -> float | None:
    if not 0 < prevalence < 1:
        raise ValueError("Prevalence must lie strictly between 0 and 1")
    if tpr is None or fpr is None:
        return None
    denominator = tpr * prevalence + fpr * (1 - prevalence)
    return tpr * prevalence / denominator if denominator > 0 else None


def summarize(predictions: list[dict]) -> dict:
    scored = [row for row in predictions if row["available"]]
    tp = sum(row["label"] == 1 and row["prediction"] is True for row in scored)
    fn = sum(row["label"] == 1 and row["prediction"] is False for row in scored)
    fp = sum(row["label"] == 0 and row["prediction"] is True for row in scored)
    tn = sum(row["label"] == 0 and row["prediction"] is False for row in scored)
    tpr = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    precision = tp / (tp + fp) if tp + fp else None
    benign_hours = sum(row["window_seconds"] for row in scored if row["label"] == 0) / 3600
    all_positive = sum(row["label"] == 1 for row in predictions)
    all_benign = sum(row["label"] == 0 for row in predictions)
    delays = [row["detection_seconds"] for row in scored
              if row["label"] == 1 and row["prediction"] is True]
    return {
        "n_total": len(predictions), "n_scored": len(scored),
        "unscored": len(predictions) - len(scored),
        "coverage": len(scored) / len(predictions) if predictions else None,
        "positive_coverage": (tp + fn) / all_positive if all_positive else None,
        "benign_coverage": (fp + tn) / all_benign if all_benign else None,
        "all_positive_detection_fraction": tp / all_positive if all_positive else None,
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "tpr": tpr, "fpr": fpr, "precision": precision,
        "tpr_ci95": wilson(tp, tp + fn), "fpr_ci95": wilson(fp, fp + tn),
        "benign_client_hours": benign_hours,
        "false_alerts_per_benign_client_hour": fp / benign_hours if benign_hours else None,
        "median_detection_seconds": statistics.median(delays) if delays else None,
        "observed_prevalence": (tp + fn) / len(scored) if scored else None,
        "prevalence_scenarios": [
            {"assumed_prevalence": p, "adjusted_precision": adjusted_precision(tpr, fpr, p)}
            for p in (0.5, 0.1, 1 / 51, 0.01, 0.001)
        ],
    }
