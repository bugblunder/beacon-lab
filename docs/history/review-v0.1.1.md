# Review corrections — v0.1.1 (historical)

This is an archived review, not current feature status. See [current verification](../../VERIFICATION.md).

This update addresses the minimum-prefix setting, the interpretation of client
novelty, and what the project has actually checked for reproducibility.
The original pilot observations, manifest, and frozen model are retained.

## 1. Minimum-prefix sensitivity

The included pilot uses min_events = 6. This was a default, not a value selected
by a sensitivity study. No sweep has been run. The write-up and generated report
now say so explicitly. TPR, FPR, coverage, and delay may all be affected for the
timing baselines; client novelty reads available signals without this gate.

Future work should compare predeclared values, distinguish fixed-threshold
comparisons from threshold refitting, and use fresh held-out runs to confirm any
choice. The existing pilot must not become an undeclared tuning set.

## 2. Client population audit

Evidence: examples/pilot/manifest.json and examples/pilot/features.jsonl.
The runner used one Python process with the standard-library http.client stack.
The recorded runtime is Python 3.12.14, OpenSSL 3.5.8 on Linux.

| Benign population | Runs | Available signals | Missing signals | Distinct values |
|---|---:|---:|---:|---:|
| HTTP development | 6 | 89 | 0 | 1 UA |
| HTTP test | 9 | 132 | 0 | 1 UA |
| HTTPS development | 6 | 87 | 0 | 1 JA3 |
| HTTPS test | 9 | 130 | 0 | 1 JA3 |

Both HTTP splits contain **BeaconLab-ResearchClient/1.0**. Both HTTPS splits
contain **dbb158bbf02cb040164d288c9b1d8492**. These comparisons use signals retained
inside each observation window. Runtime metadata is global, not an independent
package inventory for every connection. The same fingerprint does not establish
software identity or version on its own.

Client novelty measures whether a signal is absent from the benign-development
reference set. Its results depend on the coverage and changes in that client
population. It cannot determine whether an unseen client is malicious.
A new test demonstrates that changing the fingerprint of a benign test client
can trigger an alert without changing its benign label.

## 3. Repeated-run persistence

Before this review, test_core.py checked repeatability of one generated schedule
in memory. It did not establish repeatability of saved experiments.

The updated tests cover all five schedule profiles, verify that changing the seed
changes generated inputs, and round-trip the configuration through JSON storage.
An integration test launches the same small HTTP configuration in two separate
Python processes with different interpreter hash seeds. After each exits, it
reloads the files and compares:

- Configuration and generator hashes.
- The persisted plan bytes and plan hash.
- Ordered run IDs, splits, profiles, seeds, transports, and planned request counts.
- Hashes of the generated request schedules, including offsets and message inputs.

The runner now saves plan.json and the associated hashes for new experiments.
The original pilot predates these fields; they have not been backfilled.

Observed timings, ports, TLS randomness, measurements, fitted thresholds, and
metrics are outside the equality assertion. Their variability is a research
question, not a failed seed guarantee. No statistical claim of live-run stability
is made by this test, and repeated seeds are not independent synthetic workloads.

Run the checks from the project directory:

~~~sh
python -m unittest discover -s tests -v
~~~

See [the historical verification record](verification-v0.1.1.md) for checks at that time.
