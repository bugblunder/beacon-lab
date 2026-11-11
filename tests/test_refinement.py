import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from beaconlab.evaluation import evaluate
from beaconlab.metrics import summarize
from beaconlab.models import fit, predict, select_combined
from beaconlab.runner import validate_config
from beaconlab.storage import read_json, write_json, write_jsonl


def record(values, *, transport="http"):
    return {"transport": transport, "client_signals": [], "prefixes": [
        {"n_events": 10 + i, "elapsed_seconds": float(i + 1),
         "interval_cv": value, "request_size_cv": .02}
        for i, value in enumerate(values)]}


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.rule = {"kind": "timing_and_size", "interval_cv_max": .1,
                     "request_size_cv_max": .03, "min_events": 10,
                     "consecutive_prefixes": 3}

    def test_transient_match_and_reset_do_not_alert(self):
        self.assertFalse(predict(record([.05, .05, .5, .05, .05]), self.rule)["prediction"])

    def test_third_consecutive_match_is_first_alert(self):
        outcome = predict(record([.5, .05, .05, .05, .5]), self.rule)
        self.assertTrue(outcome["prediction"])
        self.assertEqual(outcome["detection_seconds"], 4)

    def test_later_observations_cannot_erase_or_move_an_alert(self):
        short = record([.05, .05, .05])
        long = record([.05, .05, .05, .9, .9])
        self.assertEqual(predict(short, self.rule), predict(long, self.rule))

    def test_short_window_is_unavailable_not_negative(self):
        self.assertFalse(predict(record([.05, .05]), self.rule)["available"])
        early = record([.05] * 4)
        for prefix in early["prefixes"]:
            prefix["n_events"] -= 5
        self.assertFalse(predict(early, self.rule)["available"])

    def test_missing_observation_breaks_persistence(self):
        self.assertFalse(predict(record([.05, .05, None, .05, .05, .5]), self.rule)["prediction"])

    def test_transport_dispatch_and_unknown_transport(self):
        rule = {"kind": "by_transport", "transport_rules": {
            "http": self.rule, "https": {**self.rule, "request_size_cv_max": .01}}}
        self.assertTrue(predict(record([.05] * 3), rule)["prediction"])
        self.assertFalse(predict(record([.05] * 3, transport="https"), rule)["prediction"])
        self.assertFalse(predict(record([.05] * 3, transport="other"), rule)["available"])

    def test_unknown_rule_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unknown rule"):
            predict(record([.05] * 3), {"kind": "misspelled"})


def selection_fixture():
    runs, records = [], []
    for split in ("development", "test"):
        for i, (label, value) in enumerate(((1, .08), (1, .09), (0, .01), (0, .8))):
            run_id = f"{split}-{i}"
            runs.append({"run_id": run_id, "split": split, "label": label,
                         "status": "complete", "transport": "http", "window_seconds": 5})
            records.append({"run_id": run_id, **record([value] * 3)})
    return {"runs": runs, "config": {"min_events": 6, "refinement": {
        "min_events": 10, "consecutive_prefixes": 3, "max_development_fpr": .1}}}, records


class SelectionTests(unittest.TestCase):
    def test_budget_does_not_report_no_alert_as_successful_detection(self):
        manifest, records = selection_fixture()
        development = [row for row in manifest["runs"] if row["split"] == "development"]
        by_id = {row["run_id"]: row for row in records}
        unconstrained = select_combined(development, by_id, min_events=10, consecutive_prefixes=3)
        constrained = select_combined(development, by_id, min_events=10, consecutive_prefixes=3, max_fpr=.1)
        self.assertEqual(unconstrained["development"]["tpr"], 1)
        self.assertEqual(unconstrained["development"]["fpr"], .5)
        self.assertEqual(constrained["selection_status"], "no_useful_development_rule")
        self.assertEqual(constrained["development"]["tpr"], 0)
        self.assertEqual(constrained["development"]["fpr"], 0)
        self.assertEqual(constrained["development"]["coverage"], 1)

    def test_all_refined_models_ignore_held_out_labels_and_features(self):
        manifest, records = selection_fixture()
        first = fit(manifest, records)
        changed = copy.deepcopy(manifest)
        changed_records = copy.deepcopy(records)
        for run in changed["runs"]:
            if run["split"] == "test":
                run["label"] = 1 - run["label"]
                run["profile"] = "not_a_predictor"
        for row in changed_records[4:]:
            row["prefixes"] = []
        self.assertEqual(first, fit(changed, changed_records))
        self.assertEqual(len(first["rules"]), 6)

    def test_selector_rejects_test_rows(self):
        manifest, records = selection_fixture()
        with self.assertRaisesRegex(ValueError, "development runs only"):
            select_combined(manifest["runs"], {row["run_id"]: row for row in records},
                            min_events=10, consecutive_prefixes=3)

    def test_refinement_config_rejects_invalid_gates_and_budget(self):
        config = read_json(Path(__file__).parents[1] / "configs/refined_pilot.json")
        for key, value in (("min_events", 5), ("consecutive_prefixes", 0),
                           ("max_development_fpr", float("nan")),
                           ("max_development_fpr", True)):
            changed = copy.deepcopy(config)
            changed["refinement"][key] = value
            with self.assertRaises(ValueError):
                validate_config(changed)

    def test_coverage_exposes_unscored_positives(self):
        rows = [{"available": True, "label": 1, "prediction": True,
                 "window_seconds": 5, "detection_seconds": 2},
                {"available": False, "label": 1, "prediction": None,
                 "window_seconds": 5, "detection_seconds": None}]
        result = summarize(rows)
        self.assertEqual(result["tpr"], 1)
        self.assertEqual(result["positive_coverage"], .5)
        self.assertEqual(result["all_positive_detection_fraction"], .5)

    def test_evaluation_rejects_modified_frozen_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "model.json", {"training_run_ids": ["development"]})
            original_hash = hashlib.sha256((root / "model.json").read_bytes()).hexdigest()
            write_json(root / "manifest.json", {"model_sha256": original_hash,
                "runs": [{"run_id": "test", "split": "test", "status": "complete"}]})
            write_jsonl(root / "features.jsonl", [{"run_id": "test"}])
            with (root / "model.json").open("a") as file:
                file.write("\n")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                evaluate(root)


if __name__ == "__main__":
    unittest.main()
