# Verification record — v0.1.1 (historical)

Archived checks for that release. See [current verification](../../VERIFICATION.md).

This record distinguishes checks performed during the build from integrations
that still require validation on a suitable local machine.

## Executed checks

| Check | Result |
|---|---|
| Python unittest suite | 28 tests passed; 0 skipped; 11.642 seconds |
| Seeded schedules | All five workload profiles repeat for the same seed; different seeds change generated inputs |
| Persisted repeated experiments | Two separate Python processes ran the same four-run HTTP configuration; saved plan bytes, config/generator/plan hashes, and per-run schedule hashes matched |
| Client-novelty interpretation | Regression test confirms a previously unseen benign fingerprint also triggers an alert |
| Benign population audit | Recorded runtime shared; benign development/test UA and JA3 sets match, with no missing retained signals |
| Actual HTTP exchanges | Passed; visible HTTP User-Agent and transferred byte counts checked |
| Actual HTTPS exchanges | Passed; certificate verification, stable JA3, and absence of plaintext HTTP headers checked |
| Experiment orchestration | Development/test separation and freeze-before-test verified |
| Included quickstart | 50 completed runs: 20 development, 30 held out; no failed runs |
| Recorded traffic | 784 actual observed TCP connections across the pilot |
| Data integrity | Configuration/model hashes match; no training/test ID overlap; model unchanged by evaluation |
| Reporting | HTML structure, linked figures, placeholder removal, and base-rate JavaScript checked |
| Scientific plots | PNG/SVG generation succeeded; detection-rate plot visually inspected |
| Temporary certificates | Removed after experiment completion |

The suite covers timing/feature causality, model selection independence from
held-out data, fingerprint parsing, metric denominators, undefined precision,
Wilson-interval boundaries, rejected message schemas, and experiment lifecycle.

Zeek JSON mapping uses schema fixtures. Capture process failure/empty-output
handling uses stub processes. These tests do not substitute for live integrations.

The persisted-input check does not require live measurements, fitted thresholds,
or metrics to be identical. It verifies a fixed generator's planned inputs in
the same runtime, not statistical stability or independent workload diversity.
See [the historical review](review-v0.1.1.md) for the audit and precise scope.

## Pilot findings

| Detector | Held-out TPR | Held-out FPR | Held-out precision |
|---|---:|---:|---:|
| Timing | 100.0% | 66.7% | 50.0% |
| Timing + size | 100.0% | 50.0% | 57.1% |
| Client novelty | 0.0% | 0.0% | Undefined: no alerts |

All three detectors had 100% scoring coverage in this pilot. The held-out set
contains 12 positive and 18 benign runs. These are small synthetic samples;
the report supplies confidence intervals and per-transport results.

This is the original v0.1.0 collection. Its observations, feature inputs,
manifest, frozen model, and numerical metric groups are unchanged in this update.
The report was regenerated with v0.1.1 to include the corrected interpretation.
New plan/hash fields apply to new experiments and were not backfilled into the
original manifest.

At a hypothetical ratio of 1 positive to 50 benign windows, the combined rule's
measured rates imply approximately 3.8% precision. This assumes unchanged rates
and is not an estimate of actual malicious-traffic prevalence.

## Not executed here

- A min_events sensitivity sweep: 6 remains an untuned pilot default.
- A statistical study of live-run stability or reproducibility across Python/OpenSSL versions.
- Live tcpdump capture, Wireshark/tshark, and Zeek: tools were absent and raw packet access was unavailable.
- Docker image build/run: Docker was absent.
- Windows/macOS execution: the build environment was Linux.
- Full browser layout/accessibility testing: no browser executable was installed. HTML/JavaScript checks were performed without a browser.
- SIEM integration, a real C2 framework, external targets, or production-network evaluation.

The included pilot therefore reports **active TCP stream observations**, not
passive packet-capture results. Its ground-truth labels describe synthetic
workloads rather than malicious intent.

Runtime: Python 3.12.14 on Linux; local OpenSSL used for HTTPS. See the pilot's
manifest.json for the recorded experiment runtime, seeds, timestamps, and hashes.
