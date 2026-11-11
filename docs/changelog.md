# Changelog

## 2.2

- Re-version the published package and release tag as `2.2` / `v2.2`.
- Keep the v0.2.0 study provenance and all historical collection records unchanged.
- Remove Docker packaging references; the supported workflow is direct Python installation and execution.


## 0.2.1

- Shorten the README and put synthetic scope, headline result and caveat first.
- Move setup/change/history documentation under docs and refresh current method/status text.
- Label historical and current example evidence without changing recorded results.
- Add GitHub CI, contribution templates, repository checks and clean release packaging.
- Generate checksums only for release archives; ignore local artifacts and preserve evidence line endings.

## 0.2.0

- Preserve the complete original pilot and all workload generators.
- Add separate HTTP/HTTPS calibration, a later-gate/persistence variant, and
  selection constrained by an empirical development false-positive budget.
- Freeze all six policies before a fresh 60-development / 100-test study.
- Add per-class coverage and paired alert changes on the same held-out runs.
- Add a read-only-source `audit` command with false-positive evidence, feature
  distributions, development-only sensitivity, and structured JSONL alerts.
- Check frozen-model integrity and record analysis/protocol hashes.
- Improve reports and document which changes helped, did not help, or eliminated
  useful recall. Record the remaining validation gaps.
- Expand the test suite from 28 to 45 tests.

See [the measured findings](refinement-findings.md) for the measured results. No production C2
detection or live SIEM integration claim is made.
