"""Seeded synthetic workloads. Profile labels never enter network messages."""
from __future__ import annotations

import http.client
import json
import random
import ssl
import time

PROFILES = {
    "channel_regular": {
        "label": 1, "family": "simulated_channel", "interval_factor": 1.0,
        "variation": 0.05, "padding": [128, 160], "description": "Regular synthetic channel",
    },
    "channel_variable": {
        "label": 1, "family": "simulated_channel", "interval_factor": 1.0,
        "variation": 0.45, "padding": [128, 192], "description": "Variable synthetic channel",
    },
    "health_check": {
        "label": 0, "family": "health_check", "interval_factor": 1.35,
        "variation": 0.03, "padding": [128, 160], "description": "Benign periodic health check",
    },
    "monitor_heartbeat": {
        "label": 0, "family": "monitor_heartbeat", "interval_factor": 1.0,
        "variation": 0.30, "padding": [96, 512], "description": "Benign monitoring heartbeat",
    },
    "update_check": {
        "label": 0, "family": "update_check", "interval_factor": 1.2,
        "variation": 0.40, "padding": [128, 768], "description": "Benign bursty update checker",
    },
}


def schedule(profile_name: str, duration: float, base_interval: float, seed: int) -> list[dict]:
    if profile_name not in PROFILES:
        raise ValueError("Unknown workload profile")
    if not 0.1 <= duration <= 600 or not 0.02 <= base_interval <= 30:
        raise ValueError("Duration must be 0.1..600 seconds and interval 0.02..30 seconds")
    profile = PROFILES[profile_name]
    rng = random.Random(seed)
    elapsed = 0.0
    items = []
    # All clients start at the same point in the window and use the same stack.
    while elapsed < duration:
        padding = rng.randint(*profile["padding"])
        items.append({"offset": elapsed, "padding": padding, "sample": f"{rng.getrandbits(64):016x}"})
        mean_interval = base_interval * profile["interval_factor"]
        delta = mean_interval * (1 + rng.uniform(-profile["variation"], profile["variation"]))
        if profile_name == "update_check":
            delta *= 0.3 if len(items) % 3 else 2.4
        elapsed += max(0.01, delta)
        if len(items) > 5000:
            raise ValueError("Workload exceeds the 5,000-request per-run limit")
    return items


def execute(plan: list[dict], port: int, transport: str, duration: float, certificate=None) -> dict:
    """Only communicate with a loopback endpoint created by the experiment runner."""
    if transport not in {"http", "https"}:
        raise ValueError("Unsupported transport")
    context = None
    if transport == "https":
        context = ssl.create_default_context(cafile=str(certificate))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    start_wall, start_mono = time.time(), time.monotonic()
    sent = completed = 0
    failures = []
    lateness = []
    for item in plan:
        target = start_mono + item["offset"]
        remaining = target - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        if time.monotonic() >= start_mono + duration:
            break
        lateness.append(max(0.0, time.monotonic() - target))
        body = json.dumps({"sample": item["sample"], "padding": "x" * item["padding"]},
                          separators=(",", ":")).encode()
        connection = (http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=5)
                      if transport == "https" else
                      http.client.HTTPConnection("127.0.0.1", port, timeout=5))
        try:
            sent += 1
            connection.request("POST", "/exchange", body,
                               {"User-Agent": "BeaconLab-ResearchClient/1.0",
                                "Content-Type": "application/json", "Connection": "close"})
            response = connection.getresponse()
            reply = response.read(16385)
            if response.status != 200 or json.loads(reply).get("ok") is not True:
                raise RuntimeError("Synthetic endpoint returned an unexpected response")
            completed += 1
        except (OSError, ValueError, RuntimeError, http.client.HTTPException) as exc:
            failures.append(type(exc).__name__)
        finally:
            connection.close()
    remaining = start_mono + duration - time.monotonic()
    if remaining > 0:
        time.sleep(remaining)
    return {
        "start_ts": start_wall, "end_ts": start_wall + duration,
        "actual_finish_ts": time.time(), "planned_requests": len(plan),
        "sent_requests": sent, "completed_requests": completed, "failures": failures,
        "mean_schedule_lateness_seconds": sum(lateness) / len(lateness) if lateness else None,
    }
