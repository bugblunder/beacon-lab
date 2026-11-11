# BeaconLab

**A reproducible, Python-based lab for studying periodicity signals in synthetic HTTP/HTTPS traffic.**

BeaconLab creates controlled loopback traffic, observes TCP streams, extracts timing and byte-volume features, and evaluates frozen detection policies against simulated channel-like and benign periodic workloads. It is designed for experimentation, detector analysis, and learning—not as a production intrusion-detection system.

> **Research result, not a security verdict:** In the included v0.2 held-out study, transport-specific calibration retained 100% recall on 40 simulated-channel runs while reducing the false-positive rate from 50.0% to 33.3%. However, every held-out health-check run still triggered an alert. The labels describe generated workloads, not maliciousness.

## At a glance

- **Local-first:** generates and observes traffic on loopback; no external target is required.
- **HTTP and HTTPS:** compares transport-specific behaviour and parses TLS ClientHello metadata, including JA3-style fingerprints.
- **Reproducible evaluation:** separates development and held-out data, freezes policies, and preserves manifests, predictions, metrics, and reports.
- **Explainable outputs:** includes diagnostics, false-positive case analysis, audit reports, and optional plots.
- **Python only:** core functionality uses the Python standard library. No container runtime or Docker build is required.

## Research snapshot

The v0.2 study contains 60 development runs and 100 held-out runs (40 simulated-channel and 60 benign), with 4,495 observed TCP connections. Each policy was evaluated against all 100 held-out runs.

| Frozen policy | Recall | False-positive rate |
|---|---:|---:|
| Pooled timing + size | 100.0% | 50.0% |
| Separate HTTP/HTTPS thresholds | 100.0% | 33.3% |
| Separate thresholds + sustained evidence | 97.5% | 33.3% |
| 10% development-FPR budget | 0.0% | 0.0% |

The budget-constrained policy selected a no-alert fallback, so its precision is undefined. Sustained evidence introduced delay and missed one positive without reducing additional false alerts. The health-check result is an important limitation: benign periodic activity can resemble the generated channel workload under these features.

Read the [detailed results and uncertainty](examples/refined-pilot/RESULTS.md), [refinement findings](docs/refinement-findings.md), and [limitations](docs/limitations.md) before interpreting these numbers.

## Quick start

### Requirements

- Python **3.10 or newer**
- OpenSSL available on `PATH` for HTTPS workloads
- Linux is the platform exercised in the included verification; other platforms are not yet validated

The core package has no mandatory third-party runtime dependencies. Matplotlib is optional for charts; see `pyproject.toml` for optional extras.

### Run from the source tree

```bash
# Check local prerequisites
python -m beaconlab doctor

# Run the unit tests
python -m unittest discover -s tests -v

# Run the quick-start experiment
python -m beaconlab run --config configs/quickstart.json --output runs/quickstart

# Open the generated report in your browser
```

The report is written to `runs/quickstart/report.html`. For the longer refined-pilot study, use `configs/refined_pilot.json`; it takes several minutes. Configuration options, HTTP-only mode, audits, and optional charts are covered in the [getting-started guide](docs/getting-started.md).

### Install the package

```bash
python -m pip install .
beaconlab doctor
```

## How it works

1. **Generate:** controlled benign and simulated-channel clients exchange fixed synthetic messages with a local loopback endpoint.
2. **Observe:** an active TCP stream forwarder records connection timing and byte-volume information. This is not passive packet capture.
3. **Extract:** BeaconLab derives periodicity-oriented features and TLS ClientHello metadata.
4. **Calibrate:** policies are selected using development data and frozen before held-out evaluation.
5. **Evaluate:** reports compare recall, false-positive rate, detection delay, class coverage, and base-rate implications.
6. **Audit:** saved predictions and evidence can be re-analysed without recollecting the original experiment.

See the [architecture](docs/architecture.md) and [research protocol](docs/research-protocol.md) for implementation and methodology details.

## Repository map

| Path | Contents |
|---|---|
| `beaconlab/` | Core Python package and CLI |
| `configs/` | Quick-start, HTTP-only, refined-pilot, and research configurations |
| `tests/` | Unit and regression tests |
| `examples/` | Reviewed synthetic datasets, manifests, metrics, reports, and audit outputs |
| `docs/` | Architecture, methodology, findings, limitations, references, and publishing notes |
| `.github/workflows/` | GitHub Actions checks for supported Python versions |
| `scripts/` | Repository hygiene checks and source-release packaging |

## Validation and scope

The included verification records the checks actually run, including the test suite, repository/evidence checks, CLI diagnostics, and source packaging. The GitHub Actions workflow is configured for Python 3.10, 3.12, and 3.14; its first hosted run must still pass after publication.

BeaconLab does **not** establish production C2 detection capability. Synthetic workload labels are not ground-truth maliciousness labels; periodic health checks can trigger alerts; the observer is an active forwarder; and the study was run on a shared host. Live PCAP/Zeek equivalence, SIEM ingestion, Windows/macOS behaviour, independently sourced traffic, and operational false-alert rates remain unvalidated. See [VERIFICATION.md](VERIFICATION.md) and [docs/limitations.md](docs/limitations.md).

## Contributing

Issues and pull requests are welcome for reproducible bugs, documentation improvements, and carefully scoped experiments. Please preserve frozen evidence, document the provenance of new datasets, and do not present synthetic labels as real-world attack ground truth. See the [publishing and contribution guide](docs/publishing.md) and the pull-request template.

## License

No license is currently declared in this repository. Unless the project owner adds a license, standard copyright restrictions apply; please do not assume the code is available for unrestricted reuse.
