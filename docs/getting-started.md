# Run BeaconLab

This guide covers the current v0.2 workflow. Read the [README](../README.md) for
the result and [VERIFICATION](../VERIFICATION.md) for the validation boundary.
Commands below run from the repository root.

## Inspect the included result

Start with [the v0.2 results](../examples/refined-pilot/RESULTS.md). After cloning
or extracting the project, open `examples/refined-pilot/report.html` in a local
browser, keeping its `figures/` directory alongside it. GitHub displays HTML
source; it does not run the report as a website.

The base-rate calculator is hypothetical. At an assumed ratio of one positive
to 50 benign windows, calibration alone gives about 5.7% precision if the measured
rates transfer unchanged. This is not a measured production prevalence.

## Check the environment

Use Python 3.10 or later and OpenSSL on PATH for HTTPS. Core commands need no
third-party Python packages or installation when run from the repository root.

```sh
python -m beaconlab doctor
python -m unittest discover -s tests -v
```

On systems where Python is named `python3`, use that command instead. Windows
may use `py -3`; Windows/macOS execution still needs platform validation.

## Choose an experiment

| Configuration | Purpose | Approximate duration |
|---|---|---:|
| `configs/quickstart.json` | Smoke run of the three original baseline policies | 2 minutes |
| `configs/http_only.json` | HTTP-only smoke run when OpenSSL is unavailable | Under 2 minutes |
| `configs/refined_pilot.json` | Six-policy comparison, 60 development / 100 test runs | 8 minutes |
| `configs/research.json` | Longer windows for the original three baseline policies | 60 minutes |

All configurations generate synthetic workloads. Choose a new output directory
for each experiment; the runner refuses to overwrite an existing study.

```sh
python -u -m beaconlab run --config configs/refined_pilot.json --output runs/my-study
python -m beaconlab audit --run-dir runs/my-study --output runs/my-study-audit
```

Open `runs/my-study/report.html` and read `runs/my-study-audit/AUDIT.md`.
Local `runs/` outputs are excluded from Git and release archives. The audit
explains individual false alerts and performs a development-only sensitivity
analysis without changing the frozen model.

## Optional plots and installation

A virtual environment is recommended if installing extras. The standard-library
core works without Matplotlib; the HTML tables and calculator remain available.

```sh
python -m pip install '.[plots]'
python -m beaconlab evaluate --run-dir runs/my-study
```

This installs the package and plotting extra. For a core-only installation:

```sh
python -m pip install .
beaconlab doctor
```

Re-evaluation reuses saved features and the frozen model. To examine bundled
studies, send regenerated output to `runs/` so the published evidence stays intact:

```sh
python -m beaconlab evaluate --run-dir examples/refined-pilot --output runs/replayed-study
```

## Follow a decision through the code

| File | Responsibility |
|---|---|
| `beaconlab/traffic.py` | Five workloads with shared client and message formats |
| `beaconlab/features.py` | Measurements available at each decision time |
| `beaconlab/models.py` | Fixed grids, development-only fitting, and prediction |
| `beaconlab/metrics.py` | Denominators, uncertainty, and hypothetical prevalence |
| `beaconlab/diagnostics.py` | False-alert evidence and development sensitivity |

The [method](research-protocol.md) explains the split and rule policies. Optional
[packet capture/Zeek](wireshark-zeek.md) guidance describes paths that still require
live integration validation. The [evidence catalog](../examples/README.md) identifies
current results and preserved historical artifacts.
