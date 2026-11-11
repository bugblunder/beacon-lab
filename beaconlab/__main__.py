from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys

from .evaluation import evaluate
from .diagnostics import audit_experiment
from .metrics import adjusted_precision
from .report import create_report
from .runner import run_experiment
from .zeek_import import import_logs


def main(argv=None):
    parser = argparse.ArgumentParser(description="BeaconLab: local traffic simulation and detection research")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Generate real local traffic, freeze rules, evaluate held-out runs")
    run.add_argument("--config", type=Path, default=Path("configs/quickstart.json"))
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--pcap", action="store_true", help="Also capture actual packets using installed tcpdump")
    run.add_argument("--interface", default="lo", help="Capture interface; use lo0 on macOS")
    run.add_argument("--no-charts", action="store_true")
    ev = sub.add_parser("evaluate", help="Evaluate frozen rules; never refit on held-out data")
    ev.add_argument("--run-dir", type=Path, required=True)
    ev.add_argument("--features", type=Path)
    ev.add_argument("--model", type=Path)
    ev.add_argument("--output", type=Path)
    ev.add_argument("--no-charts", action="store_true")
    audit = sub.add_parser("audit", help="Diagnose false positives and development sensitivity without changing source data")
    audit.add_argument("--run-dir", type=Path, required=True)
    audit.add_argument("--output", type=Path, required=True)
    audit.add_argument("--no-charts", action="store_true")
    imp = sub.add_parser("import-zeek", help="Import actual Zeek JSON logs using the experiment manifest")
    imp.add_argument("--logs", type=Path, required=True)
    imp.add_argument("--run-dir", type=Path, required=True)
    imp.add_argument("--output", type=Path, required=True)
    sub.add_parser("doctor", help="Show optional tool availability without starting traffic")
    rate = sub.add_parser("base-rate", help="Compute precision for explicit assumed rates")
    rate.add_argument("--tpr", type=float, required=True)
    rate.add_argument("--fpr", type=float, required=True)
    rate.add_argument("--prevalence", type=float, default=1 / 51)
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            print(json.dumps({"python": sys.version, "optional_tools": {
                name: shutil.which(name) for name in ("openssl", "tcpdump", "zeek", "tshark")
            }, "default_mode": "actual loopback HTTP/S via TCP stream observer"}, indent=2))
        elif args.command == "run":
            run_experiment(args.config, args.output, pcap=args.pcap, interface=args.interface)
            manifest, model, summary = evaluate(args.output)
            create_report(args.output, manifest, model, summary, charts=not args.no_charts)
            print(f"Completed: {args.output / 'report.html'}")
        elif args.command == "evaluate":
            destination = args.output or args.run_dir
            manifest, model, summary = evaluate(args.run_dir, feature_file=args.features,
                                                model_file=args.model, output=destination)
            create_report(destination, manifest, model, summary, charts=not args.no_charts)
            print(f"Report: {destination / 'report.html'}")
        elif args.command == "import-zeek":
            print(json.dumps(import_logs(args.logs, args.run_dir, args.output), indent=2))
        elif args.command == "audit":
            audit_experiment(args.run_dir, args.output, charts=not args.no_charts)
            print(f"Audit: {args.output / 'AUDIT.md'}")
        else:
            if not 0 <= args.tpr <= 1 or not 0 <= args.fpr <= 1:
                raise ValueError("TPR and FPR must be between 0 and 1")
            print(json.dumps({"assumed_prevalence": args.prevalence,
                              "adjusted_precision": adjusted_precision(args.tpr, args.fpr, args.prevalence)}, indent=2))
        return 0
    except KeyboardInterrupt:
        print("Stopped; completed runs and the partial manifest were preserved.", file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"BeaconLab: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
