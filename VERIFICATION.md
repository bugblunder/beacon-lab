# Verification — v0.2.1

This release prepares the repository for GitHub. It does not change detector
logic or recollect the v0.2 study. Results and interpretation are in
[the findings](docs/refinement-findings.md).

## Executed locally

| Check | Result |
|---|---|
| Python suite | 45 tests passed on Python 3.12.14 / Linux |
| Original evidence | All 63 original pilot files preserved byte-for-byte; a README labels the directory as historical |
| v0.2 evidence | Existing observations, models, metrics, reports, plots and protocol snapshot preserved |
| Prediction/evaluation | Causality, persistence, coverage, held-out isolation and model-integrity checks pass |
| Audit regression | Original false alerts and numerical metric groups reproduce unchanged |
| Repository checks | Relative links, source-file hygiene and recorded evidence hashes checked |
| Installation | Core wheel built offline; installed package and console command exercised outside the source tree |
| Packaging | Source ZIP contents and generated file hashes verified; local outputs excluded |

The included v0.2 collection completed 160 loopback HTTP/HTTPS runs (60 development,
100 test), recording 4,495 stream-observer connections with no failed runs. All
six policies were frozen before held-out collection. Its runtime, timestamps,
configuration and source/model hashes are retained in
[the manifest](examples/refined-pilot/manifest.json).

The GitHub workflow is configured for Linux and Python 3.10, 3.12 and 3.14.
**It has not yet run on GitHub.** Only the local Python version above has been
exercised here; a configured matrix is not evidence of a passed matrix.

## Validation still outstanding

- Windows/macOS execution and cross-machine/day stability.
- Live tcpdump/Wireshark/Zeek capture and equivalence with the stream observer.
- Live SIEM ingestion. JSONL export alone is not integration.
- Production or independently sourced traffic and operational false-alert rates.
- Full browser layout/mobile/accessibility QA. Chromium startup was blocked by
  the execution environment; HTML/assets, calculator JavaScript and scientific
  plots were checked separately during v0.2 preparation.

The experiment ran on a shared host and uses an active TCP forwarder, not passive
packet capture. Synthetic generators and shared runtime limit external validity.

## Historical records

The [v0.1.1 verification](docs/history/verification-v0.1.1.md) and
[review](docs/history/review-v0.1.1.md) describe that release's status, not today's.
See the [evidence catalog](examples/README.md) for current versus historical
artifacts and the [changelog](docs/changelog.md) for repository changes.

## Additional pre-publication checks (2026-11-11)

The following checks were run during preparation of the GitHub repository on
Python 3.13.5 / Linux:

| Check | Result |
|---|---|
| Unit tests | 45/45 passed |
| Repository hygiene/evidence checker | Passed; 321 reviewed source files after removal of container-only files |
| CLI help and environment diagnostics | Passed; OpenSSL available |
| Retrospective audit of `examples/refined-pilot` | Completed successfully |
| Source release packaging | Completed; generated archive and checksum |

A fresh quick-start workload was started but did not complete within the hosted
execution time limit. No pass/fail result is claimed for that run. Optional
system tools such as tcpdump, Zeek, tshark, and Docker were not available in the
preparation environment. Docker is not a project requirement and is not part of
the published workflow. The GitHub Actions matrix remains pending its first
hosted execution.
