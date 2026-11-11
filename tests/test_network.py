from contextlib import closing
from datetime import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from beaconlab.evaluation import evaluate
from beaconlab.features import build_record
from beaconlab.network import Controller, StreamObserver
from beaconlab.report import create_report
from beaconlab.runner import run_experiment
from beaconlab.storage import read_json, write_json
from beaconlab.tls import make_local_certificate
from beaconlab.traffic import execute, schedule


class NetworkTests(unittest.TestCase):
    def exercise(self, transport):
        with tempfile.TemporaryDirectory() as temporary:
            cert, key = make_local_certificate(Path(temporary)) if transport == "https" else (None, None)
            with closing(Controller(certificate=cert, private_key=key)) as controller:
                with closing(StreamObserver(controller.port, transport)) as observer:
                    observer.begin("network-test")
                    stats = execute(schedule("health_check", .8, .06, 42),
                                    observer.port, transport, .8, cert)
                    flows = observer.end()
            self.assertGreaterEqual(stats["completed_requests"], 6)
            self.assertEqual(stats["failures"], [])
            self.assertEqual(len(flows), stats["completed_requests"])
            self.assertTrue(all(row["orig_bytes"] > 0 and row["resp_bytes"] > 0 for row in flows))
            self.assertTrue(all(row["error"] is None for row in flows), flows)
            return flows, stats

    def test_real_http_observations(self):
        flows, _ = self.exercise("http")
        self.assertTrue(all(row["user_agent"] == "BeaconLab-ResearchClient/1.0" for row in flows))
        self.assertTrue(all(row["ja3"] is None for row in flows))

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is optional")
    def test_real_https_observations_and_no_plaintext_header_leak(self):
        flows, _ = self.exercise("https")
        self.assertTrue(all(row["user_agent"] is None for row in flows))
        fingerprints = {row["ja3"] for row in flows}
        self.assertNotIn(None, fingerprints)
        self.assertEqual(len(fingerprints), 1)

    def test_endpoint_accepts_only_the_fixed_synthetic_schema(self):
        with closing(Controller()) as controller:
            conn = http.client.HTTPConnection("127.0.0.1", controller.port, timeout=3)
            conn.request("POST", "/exchange", json.dumps({"action": "unrecognized"}),
                         {"Content-Type": "application/json"})
            response = conn.getresponse()
            self.assertEqual(response.status, 400)
            response.read()
            conn.close()

    def test_full_runner_freezes_before_held_out_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = {
                "seed": 94, "window_seconds": .8, "base_interval_seconds": .06,
                "development_repetitions": 1, "test_repetitions": 1,
                "profiles": ["channel_regular", "health_check"], "transports": ["http"], "min_events": 6,
            }
            write_json(root / "config.json", config)
            manifest = run_experiment(root / "config.json", root / "run", progress=lambda *_: None)
            self.assertEqual(manifest["status"], "complete")
            frozen = datetime.fromisoformat(manifest["model_frozen_utc"]).timestamp()
            self.assertTrue(all(row["start_ts"] >= frozen for row in manifest["runs"] if row["split"] == "test"))
            data, model, summary = evaluate(root / "run")
            self.assertEqual(summary["n_test"], 2)
            create_report(root / "run", data, model, summary, charts=False)
            page = (root / "run/report.html").read_text()
            self.assertIn("tcp_stream_proxy", page)
            self.assertNotIn("@@", page)
            self.assertFalse(list((root / "run").glob("local-tls-*")))
            # The same evaluation must not mutate/refit the frozen model.
            original = (root / "run/model.json").read_bytes()
            evaluate(root / "run")
            self.assertEqual(original, (root / "run/model.json").read_bytes())

    def test_evaluation_rejects_training_test_overlap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "manifest.json", {"runs": [{"run_id": "r1", "split": "test",
                                                        "status": "complete"}]})
            write_json(root / "model.json", {"training_run_ids": ["r1"]})
            (root / "features.jsonl").write_text('{"run_id":"r1"}\n')
            with self.assertRaisesRegex(ValueError, "Leakage"):
                evaluate(root)

    def test_same_seed_repeats_persisted_inputs_across_processes(self):
        # Real HTTP experiments in separate interpreters. Equality applies to
        # planned inputs, never to live timings, TLS randomness, or fitted rules.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = {
                "seed": 8304, "window_seconds": .8, "base_interval_seconds": .04,
                "development_repetitions": 1, "test_repetitions": 1,
                "profiles": ["channel_variable", "health_check"],
                "transports": ["http"], "min_events": 6,
            }
            write_json(root / "config.json", config)
            outputs = [root / "first", root / "second"]
            for index, output in enumerate(outputs):
                environment = {**os.environ, "PYTHONHASHSEED": str(17 + index)}
                completed = subprocess.run(
                    [sys.executable, "-m", "beaconlab", "run", "--config", str(root / "config.json"),
                     "--output", str(output), "--no-charts"],
                    cwd=Path(__file__).parents[1], env=environment,
                    capture_output=True, text=True, timeout=45,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            first, second = [read_json(path / "manifest.json") for path in outputs]
            for key in ("config", "config_sha256", "plan_sha256", "generator_sha256", "runtime"):
                self.assertEqual(first[key], second[key], key)
            self.assertEqual((outputs[0] / "plan.json").read_bytes(),
                             (outputs[1] / "plan.json").read_bytes())
            stable_fields = ("run_id", "seed", "split", "profile", "label", "transport",
                             "repetition", "window_seconds", "planned_requests", "schedule_sha256")
            def inputs(manifest):
                return [{key: row[key] for key in stable_fields} for row in manifest["runs"]]
            self.assertEqual(inputs(first), inputs(second))
            for output, manifest in zip(outputs, (first, second)):
                self.assertEqual(manifest["status"], "complete")
                self.assertEqual(len(manifest["runs"]), 4)
                self.assertEqual(manifest["plan_sha256"],
                                 hashlib.sha256((output / "plan.json").read_bytes()).hexdigest())
                self.assertEqual(read_json(output / "metrics.json")["n_test"], 2)
                self.assertTrue(all(row["completed_requests"] >= 6 for row in manifest["runs"]))
                self.assertTrue(all(len(row["schedule_sha256"]) == 64 for row in manifest["runs"]))


if __name__ == "__main__":
    unittest.main()
