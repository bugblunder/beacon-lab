import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from beaconlab.features import build_record, cv, extract_prefixes
from beaconlab.metrics import adjusted_precision, summarize, wilson
from beaconlab.models import fit, predict
from beaconlab.runner import make_plan, validate_config
from beaconlab.tls import ja3_from_stream
from beaconlab.traffic import PROFILES, schedule
from beaconlab.zeek_import import import_logs
from beaconlab.storage import read_json, write_json, write_jsonl


def hello_records():
    def u16(n):
        return n.to_bytes(2, "big")
    # GREASE must not appear in the resulting cipher, extension, or group lists.
    ciphers = u16(0x0a0a) + u16(4865) + u16(4866)
    groups = u16(6) + u16(0x1a1a) + u16(29) + u16(23)
    extensions = (u16(0x2a2a) + u16(0) + u16(10) + u16(len(groups)) + groups
                  + u16(11) + u16(2) + bytes([1, 0]))
    body = u16(771) + bytes(32) + b"\x00" + u16(len(ciphers)) + ciphers + b"\x01\x00"
    body += u16(len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    def record(fragment):
        return b"\x16\x03\x01" + len(fragment).to_bytes(2, "big") + fragment
    return record(handshake), record(handshake[:18]) + record(handshake[18:])


class FingerprintTests(unittest.TestCase):
    def test_real_structure_and_grease(self):
        full, fragmented = hello_records()
        expected = "771,4865-4866,10-11,29-23,0"
        for data in (full, fragmented):
            result = ja3_from_stream(data)
            self.assertEqual(result["ja3_string"], expected)
            self.assertEqual(result["ja3"], hashlib.md5(expected.encode()).hexdigest())

    def test_truncated_and_non_tls_are_unavailable(self):
        full, _ = hello_records()
        self.assertIsNone(ja3_from_stream(full[:-1]))
        self.assertIsNone(ja3_from_stream(b"POST /exchange HTTP/1.1\r\n\r\n"))


class StatisticsTests(unittest.TestCase):
    def test_base_rate_example(self):
        self.assertAlmostEqual(adjusted_precision(.99, .05, 1 / 51), 99 / 349)

    def test_no_alert_precision_is_undefined(self):
        self.assertIsNone(adjusted_precision(0, 0, .1))

    def test_zero_observed_false_positives_has_uncertainty(self):
        low, high = wilson(0, 10)
        self.assertAlmostEqual(low, 0)
        self.assertGreater(high, .2)

    def test_boundary_intervals_contain_the_observed_rate(self):
        for total in (1, 3, 6, 9, 18, 30):
            for successes in (0, total):
                low, high = wilson(successes, total)
                self.assertLessEqual(low, successes / total)
                self.assertGreaterEqual(high, successes / total)

    def test_unavailable_is_not_a_negative_prediction(self):
        rows = [{"available": False, "label": 1, "prediction": None, "window_seconds": 60,
                 "detection_seconds": None}]
        result = summarize(rows)
        self.assertEqual(result["unscored"], 1)
        self.assertEqual(result["fn"], 0)
        self.assertIsNone(result["tpr"])

    def test_metric_denominators_and_hours(self):
        rows = [
            {"available": True, "label": label, "prediction": prediction,
             "window_seconds": 60, "detection_seconds": 4 if prediction else None}
            for label, prediction in [(1, True), (1, False), (0, True), (0, False)]
        ]
        result = summarize(rows)
        self.assertEqual((result["tp"], result["fn"], result["fp"], result["tn"]), (1, 1, 1, 1))
        self.assertEqual(result["tpr"], .5)
        self.assertEqual(result["false_alerts_per_benign_client_hour"], 30)


class FeatureTests(unittest.TestCase):
    def test_future_data_not_visible_to_early_decisions(self):
        flows = [{"ts": t, "completed_ts": t + .05, "orig_bytes": 100, "resp_bytes": 200,
                  "error": None} for t in (1, 2, 3, 4, 5, 6, 7)]
        short = extract_prefixes(flows, 0, 6.5, 6)
        self.assertEqual(len(short), 1)
        self.assertEqual(short[0]["n_events"], 6)
        self.assertAlmostEqual(short[0]["elapsed_seconds"], 6.05)

    def test_model_inputs_exclude_ground_truth_fields(self):
        run = {"run_id": "r", "transport": "http", "start_ts": 0, "end_ts": 10,
               "label": 1, "profile": "secret", "seed": 123, "observer_port": 12345}
        record = build_record(run, [])
        for key in ("label", "profile", "seed", "observer_port", "start_ts"):
            self.assertNotIn(key, record)

    def test_variation_requires_observations(self):
        self.assertIsNone(cv([1]))
        self.assertEqual(cv([1, 1, 1]), 0)


def model_fixture():
    runs, records = [], []
    for identifier, split, label, variation in [
        ("dev-positive", "development", 1, .05),
        ("dev-negative", "development", 0, .8),
        ("test-positive", "test", 1, .04),
        ("test-negative", "test", 0, .9),
    ]:
        runs.append({"run_id": identifier, "split": split, "label": label, "status": "complete"})
        records.append({
            "run_id": identifier, "transport": "https",
            "prefixes": [{"interval_cv": variation, "request_size_cv": .03,
                          "elapsed_seconds": 5, "n_events": 6}],
            "client_signals": [{"ja3": "shared-library", "user_agent": None, "elapsed_seconds": 1}],
        })
    return {"runs": runs}, records


class ModelTests(unittest.TestCase):
    def test_held_out_labels_and_features_cannot_change_fit(self):
        manifest, records = model_fixture()
        first = fit(manifest, records)
        modified_manifest, modified_records = copy.deepcopy(manifest), copy.deepcopy(records)
        for run in modified_manifest["runs"]:
            if run["split"] == "test":
                run["label"] = 1 - run["label"]
        for record in modified_records[2:]:
            record["prefixes"][0]["interval_cv"] = 999
            record["client_signals"][0]["ja3"] = "never-seen"
        self.assertEqual(first, fit(modified_manifest, modified_records))
        self.assertEqual(set(first["training_run_ids"]), {"dev-positive", "dev-negative"})

    def test_fingerprint_does_not_encode_simulated_label(self):
        manifest, records = model_fixture()
        model = fit(manifest, records)
        outcome = predict(records[2], model["rules"]["client_novelty"])
        self.assertFalse(outcome["prediction"])

    def test_unseen_benign_fingerprint_also_alerts(self):
        manifest, records = model_fixture()
        rule = fit(manifest, records)["rules"]["client_novelty"]
        benign_test = copy.deepcopy(records[3])
        self.assertEqual(manifest["runs"][3]["label"], 0)
        self.assertFalse(predict(benign_test, rule)["prediction"])
        benign_test["client_signals"][0]["ja3"] = "legitimate-new-client-stack"
        self.assertTrue(predict(benign_test, rule)["prediction"])

    def test_first_qualifying_prefix_is_the_reported_alert(self):
        rule = {"kind": "timing", "interval_cv_max": .1}
        record = {"prefixes": [
            {"interval_cv": .2, "request_size_cv": .1, "elapsed_seconds": 4},
            {"interval_cv": .05, "request_size_cv": .1, "elapsed_seconds": 5},
            {"interval_cv": .3, "request_size_cv": .1, "elapsed_seconds": 6},
        ]}
        result = predict(record, rule)
        self.assertTrue(result["prediction"])
        self.assertEqual(result["detection_seconds"], 5)


class PlanTests(unittest.TestCase):
    def test_schedule_is_reproducible_bounded_and_label_free(self):
        for profile in PROFILES:
            with self.subTest(profile=profile):
                first = schedule(profile, 2, .12, 53)
                self.assertEqual(first, schedule(profile, 2, .12, 53))
                self.assertNotEqual(first, schedule(profile, 2, .12, 54))
                self.assertTrue(all(item["offset"] < 2 for item in first))
                self.assertTrue(all(set(item) == {"offset", "sample", "padding"} for item in first))

    def test_plan_survives_config_roundtrip_and_seed_changes(self):
        config = json.loads((Path(__file__).parents[1] / "configs/quickstart.json").read_text())
        first = make_plan(validate_config(config))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            write_json(path, config)
            self.assertEqual(first, make_plan(validate_config(read_json(path))))
        changed = {**config, "seed": config["seed"] + 1}
        self.assertNotEqual(first, make_plan(validate_config(changed)))

    def test_split_has_disjoint_seeds_and_development_comes_first(self):
        config = json.loads((Path(__file__).parents[1] / "configs/quickstart.json").read_text())
        plan = make_plan(validate_config(config))
        development = [row for row in plan if row["split"] == "development"]
        tests = [row for row in plan if row["split"] == "test"]
        self.assertFalse({row["seed"] for row in development} & {row["seed"] for row in tests})
        self.assertEqual(plan[:len(development)], development)

    def test_config_rejects_unbounded_inputs(self):
        config = json.loads((Path(__file__).parents[1] / "configs/quickstart.json").read_text())
        config["window_seconds"] = float("inf")
        with self.assertRaises(ValueError):
            validate_config(config)


class ZeekImportTests(unittest.TestCase):
    def test_actual_log_schema_mapping_and_missing_tls_signal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            logs, run_dir = root / "logs", root / "run"
            run = {"run_id": "r1", "start_ts": 100, "end_ts": 110, "observer_port": 8813,
                   "transport": "https"}
            write_json(run_dir / "manifest.json", {"runs": [run], "config": {"min_events": 3}})
            write_jsonl(logs / "conn.log", [
                {"uid": "C" + str(index), "ts": 101 + index, "duration": .1,
                 "id.resp_p": 8813, "orig_bytes": 300, "resp_bytes": 600}
                for index in range(4)])
            result = import_logs(logs, run_dir, root / "import")
            self.assertEqual(result["matched_connections"], 4)
            self.assertFalse(result["ja3_available"])
            self.assertEqual(result["invalid_connections"], 0)


if __name__ == "__main__":
    unittest.main()
