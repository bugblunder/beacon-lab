from __future__ import annotations

from contextlib import ExitStack, closing
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import random
import ssl
import tempfile

from . import __version__
from .capture import PacketCapture
from .features import build_record
from .models import fit
from .network import Controller, StreamObserver
from .storage import read_json, write_csv, write_json, write_jsonl
from .tls import make_local_certificate
from .traffic import PROFILES, execute, schedule


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def validate_config(config):
    required = {"seed", "window_seconds", "base_interval_seconds", "development_repetitions",
                "test_repetitions", "profiles", "transports", "min_events"}
    if set(config) - required - {"description", "refinement"} or required - set(config):
        raise ValueError("Config has missing or unknown fields")
    for name, low, high in (("window_seconds", 0.5, 600), ("base_interval_seconds", 0.02, 30)):
        value = config[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not low <= value <= high:
            raise ValueError(f"{name} must be between {low} and {high}")
    for name in ("development_repetitions", "test_repetitions"):
        if type(config[name]) is not int or not 1 <= config[name] <= 100:
            raise ValueError(f"{name} must be an integer from 1 to 100")
    if type(config["seed"]) is not int or type(config["min_events"]) is not int or not 3 <= config["min_events"] <= 100:
        raise ValueError("Invalid seed or min_events")
    for name in ("profiles", "transports"):
        if not isinstance(config[name], list) or not config[name] or len(set(config[name])) != len(config[name]):
            raise ValueError(f"{name} must be a nonempty list with no duplicates")
    if set(config["profiles"]) - set(PROFILES) or set(config["transports"]) - {"http", "https"}:
        raise ValueError("Unknown profile or transport")
    if {PROFILES[name]["label"] for name in config["profiles"]} != {0, 1}:
        raise ValueError("Select both simulated-channel and benign profiles")
    if "refinement" in config:
        refinement = config["refinement"]
        if not isinstance(refinement, dict) or set(refinement) != {
                "min_events", "consecutive_prefixes", "max_development_fpr"}:
            raise ValueError("Invalid refinement fields")
        if (type(refinement["min_events"]) is not int
                or not config["min_events"] <= refinement["min_events"] <= 100
                or type(refinement["consecutive_prefixes"]) is not int
                or not 1 <= refinement["consecutive_prefixes"] <= 10):
            raise ValueError("Invalid refinement minimum events or consecutive prefixes")
        budget = refinement["max_development_fpr"]
        if isinstance(budget, bool) or not isinstance(budget, (int, float)) or not 0 < budget < 1:
            raise ValueError("max_development_fpr must be strictly between 0 and 1")
    return config


def make_plan(config):
    rng = random.Random(config["seed"])
    plan = []
    seen = set()
    for split, count in (("development", config["development_repetitions"]),
                         ("test", config["test_repetitions"])):
        group = []
        for transport in config["transports"]:
            for profile in config["profiles"]:
                for repetition in range(count):
                    seed = rng.getrandbits(63)
                    while seed in seen:
                        seed = rng.getrandbits(63)
                    seen.add(seed)
                    group.append({
                        "run_id": f"r{rng.getrandbits(64):016x}",
                        "seed": seed, "split": split, "profile": profile,
                        "label": PROFILES[profile]["label"], "transport": transport,
                        "repetition": repetition, "status": "pending",
                        "window_seconds": config["window_seconds"],
                    })
        rng.shuffle(group)
        plan.extend(group)
    return plan


def run_experiment(config_path: Path, output: Path, *, pcap=False, interface="lo", progress=print):
    config = validate_config(read_json(config_path))
    if output.exists():
        raise ValueError(f"Output already exists: {output}. Choose a new directory.")
    output.mkdir(parents=True)
    config_hash = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    plan = make_plan(config)
    write_json(output / "plan.json", plan)
    manifest = {
        "schema_version": 1, "project": "BeaconLab", "version": __version__,
        "started_utc": utc_now(), "finished_utc": None, "status": "collecting",
        "config": config, "config_sha256": config_hash,
        "plan_file": "plan.json",
        "plan_sha256": hashlib.sha256((output / "plan.json").read_bytes()).hexdigest(),
        "generator_sha256": hashlib.sha256(Path(__file__).with_name("traffic.py").read_bytes()).hexdigest(),
        "analysis_source_sha256": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                   for name in ("models.py", "features.py", "metrics.py", "evaluation.py")},
        "runtime": {"python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION,
                    "platform": platform.system(), "http_client": "Python standard-library http.client",
                    "client_runtime_scope": "One Python process shared by all development and test clients"},
        "measurement": {
            "primary_observer": "tcp_stream_proxy",
            "description": "Actual loopback socket traffic through an active transparent TCP forwarder",
            "byte_units": "TCP payload bytes, including TLS records; not IP packet byte counts",
            "one_request_per_connection": True,
            "pcap_requested": pcap, "pcap_file": "capture.pcap" if pcap else None,
            "raw_packet_capture_performed": False,
        },
        "runs": [],
    }
    protocol = Path(__file__).parents[1] / "docs" / "refinement-protocol.md"
    if config.get("refinement") and protocol.exists():
        (output / "protocol.md").write_bytes(protocol.read_bytes())
        manifest["protocol_sha256"] = hashlib.sha256(protocol.read_bytes()).hexdigest()
    write_json(output / "manifest.json", manifest)
    records = []
    model_frozen = False
    try:
        with ExitStack() as stack:
            private_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="local-tls-", dir=output)))
            cert, key = (make_local_certificate(private_dir) if "https" in config["transports"] else (None, None))
            endpoints = {}
            for transport in config["transports"]:
                controller = stack.enter_context(closing(Controller(
                    certificate=cert if transport == "https" else None,
                    private_key=key if transport == "https" else None)))
                observer = stack.enter_context(closing(StreamObserver(controller.port, transport)))
                endpoints[transport] = observer
            manifest["measurement"]["observer_ports"] = {key: obj.port for key, obj in endpoints.items()}
            if pcap:
                stack.enter_context(closing(PacketCapture(
                    output / "capture.pcap", [obj.port for obj in endpoints.values()], interface)))
            for index, planned in enumerate(plan):
                if planned["split"] == "test" and not model_frozen:
                    model = fit(manifest, records)
                    model["frozen_utc"] = utc_now()
                    write_json(output / "model.json", model)
                    manifest["model_frozen_utc"] = model["frozen_utc"]
                    manifest["model_sha256"] = hashlib.sha256((output / "model.json").read_bytes()).hexdigest()
                    model_frozen = True
                    progress("Rules frozen from development data. Beginning held-out runs.")
                observer = endpoints[planned["transport"]]
                traffic_plan = schedule(planned["profile"], config["window_seconds"],
                                        config["base_interval_seconds"], planned["seed"])
                schedule_hash = hashlib.sha256(json.dumps(traffic_plan, sort_keys=True).encode()).hexdigest()
                observer.begin(planned["run_id"])
                stats = execute(traffic_plan, observer.port, planned["transport"],
                                config["window_seconds"], certificate=cert)
                flows = observer.end()
                run = {**planned, **stats, "observer_port": observer.port,
                       "schedule_sha256": schedule_hash,
                       "status": "complete" if not stats["failures"] else "failed"}
                run["observer_errors"] = sum(bool(row.get("error")) for row in flows)
                run["observed_total_connections"] = len(flows)
                if run["observer_errors"]:
                    run["status"] = "failed"
                manifest["runs"].append(run)
                write_jsonl(output / "observations" / (run["run_id"] + ".jsonl"), flows)
                records.append(build_record(run, flows, config["min_events"]))
                write_jsonl(output / "features.jsonl", records)
                write_json(output / "manifest.json", manifest)
                progress(f"[{index + 1}/{len(plan)}] {run['split']:11} {run['transport']:5} "
                         f"{run['profile']:18} {stats['completed_requests']:3} exchanges | {run['status']}")
        # ExitStack has closed and validated the capture process at this point.
        manifest["measurement"]["raw_packet_capture_performed"] = bool(pcap)
        manifest["status"] = "complete" if all(run["status"] == "complete" for run in manifest["runs"]) else "complete_with_failures"
    except BaseException:
        manifest["status"] = "interrupted_or_failed"
        raise
    finally:
        manifest["finished_utc"] = utc_now()
        write_json(output / "manifest.json", manifest)
        write_jsonl(output / "features.jsonl", records)
    flat = []
    for record in records:
        last = record["prefixes"][-1] if record["prefixes"] else {}
        flat.append({"run_id": record["run_id"], "transport": record["transport"],
                     "observer": record["observer"], "observed_connections": record["observed_connections"],
                     "interval_cv": last.get("interval_cv"),
                     "request_size_cv": last.get("request_size_cv")})
    write_csv(output / "features.csv", flat)
    return manifest
