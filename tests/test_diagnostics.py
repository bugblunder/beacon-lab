import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from beaconlab.diagnostics import audit_experiment, development_sensitivity
from beaconlab.evaluation import evaluate
from beaconlab.report import conclusions
from beaconlab.storage import read_json, read_jsonl

PILOT = Path(__file__).parents[1] / "examples" / "pilot"


class DiagnosticTests(unittest.TestCase):
    def test_original_pilot_decisions_and_metrics_are_preserved(self):
        original = read_json(PILOT / "metrics.json")
        with tempfile.TemporaryDirectory() as temporary:
            _, _, evaluated = evaluate(PILOT, output=Path(temporary))
        for old, new in zip(original["groups"], evaluated["groups"]):
            for key in old:
                self.assertEqual(old[key], new[key], (old["detector"], old["transport"], key))

    def test_audit_traces_original_false_alerts_without_changing_sources(self):
        paths = list(PILOT.rglob("*"))
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
        with tempfile.TemporaryDirectory() as temporary:
            audit = audit_experiment(PILOT, Path(temporary) / "audit", charts=False)
            combined = [row for row in audit["false_positive_cases"] if row["detector"] == "timing_and_size"]
            self.assertEqual(len(combined), 9)
            self.assertEqual(sum(row["profile"] == "health_check" for row in combined), 6)
            self.assertEqual(sum(row["profile"] == "monitor_heartbeat" for row in combined), 3)
            self.assertTrue(all(row["final_prefix_still_matches"] for row in combined))
            events = read_jsonl(Path(temporary) / "audit/alerts.jsonl")
            self.assertTrue(events)
            for event in events:
                self.assertNotIn("profile", event)
                self.assertNotIn("label", event)
            test_ids = {row["run_id"] for row in read_json(PILOT / "manifest.json")["runs"] if row["split"] == "test"}
            self.assertFalse(test_ids & set(audit["sensitivity_training_run_ids"]))
        self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in before})

    def test_sensitivity_ignores_test_observations_and_labels(self):
        manifest = read_json(PILOT / "manifest.json")
        records = read_jsonl(PILOT / "features.jsonl")
        expected = development_sensitivity(manifest, records)
        changed = copy.deepcopy(manifest)
        test_ids = set()
        for run in changed["runs"]:
            if run["split"] == "test":
                run["label"] = 1 - run["label"]
                test_ids.add(run["run_id"])
        for row in records:
            if row["run_id"] in test_ids:
                row["prefixes"] = []
        self.assertEqual(expected, development_sensitivity(changed, records))
        # The old short pilot's higher gate excludes some benign runs. A zero
        # conditional FPR must remain accompanied by lower benign coverage.
        higher_gates = [row for row in expected if row["min_events"] == 14]
        self.assertTrue(any(row.get("fpr") == 0 and row.get("benign_coverage", 1) < 1
                            for row in higher_gates))

    def test_no_alert_conclusion_calls_out_zero_utility(self):
        summary = {"groups": [{"detector": "budgeted_persistent", "transport": "all",
                   "tpr": 0., "fpr": 0., "tp": 0, "fp": 0}],
                   "refinement": {"max_development_fpr": .1}, "profile_groups": []}
        text = " ".join(conclusions(summary))
        self.assertIn("precision is undefined", text)
        self.assertIn("zero alerts do not demonstrate useful detection", text)


if __name__ == "__main__":
    unittest.main()
