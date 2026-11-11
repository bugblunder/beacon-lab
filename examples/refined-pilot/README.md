# Current study — v0.2 collection

Start with [RESULTS.md](RESULTS.md) or open `report.html` locally. This saved
study contains 60 development and 100 held-out runs, collected with **v0.2.0**.
It compares six frozen policies on the same test set.

The v0.2.1 documentation/repository cleanup leaves all existing evidence intact.
`protocol.md` is the exact pre-collection snapshot; `manifest.json` records its
hash, the analysis-source hashes and the model freeze. A collection version is
provenance, not a stale package-version label.

Read [the findings](../../docs/refinement-findings.md) for interpretation and
[VERIFICATION](../../VERIFICATION.md) for current validation limits. Re-evaluate
into a separate ignored output directory to preserve these files:

```sh
python -m beaconlab evaluate --run-dir examples/refined-pilot --output runs/replay
```
