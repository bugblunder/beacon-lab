# BeaconLab v0.2 — what improved, and what did not

**Transport-specific calibration reduced false alerts in the fresh synthetic
study. Adding a later observation gate and persistence did not improve false
positives and lost one positive detection. The evaluated rule family remains
unsuitable for treating periodic traffic as confirmed malicious activity.**

## Evidence boundary

The original v0.1 pilot is preserved byte-for-byte in `examples/pilot`.
Its timing-plus-size rule detected 12/12 simulated-channel runs and flagged
9/18 benign runs. This pilot motivated the v0.2 design; it was not reused as
untouched validation for the new policies.

The fresh study collected 60 development and 100 held-out runs: 40 positive
synthetic workloads and 60 benign workloads, balanced across HTTP and HTTPS.
All 160 runs completed, with 4,495 observed TCP connections in total. The same
five workload generators were retained. All six policies were frozen before
held-out collection. Config, protocol, source and model hashes are recorded.

The table below compares policies on **the same 100 held-out runs**. Scoring
coverage was 100% for both classes under every policy.

| Policy | Detected positive runs | False alerts / benign runs | Recall | FPR | Observed precision | Median detection delay |
|---|---:|---:|---:|---:|---:|---:|
| Pooled timing | 40/40 | 40/60 | 100.0% | 66.7% | 50.0% | 0.50 s |
| Pooled timing + size | 40/40 | 30/60 | 100.0% | 50.0% | 57.1% | 0.50 s |
| Client novelty | 0/40 | 0/60 | 0.0% | 0.0% | Undefined | N/A |
| Transport calibrated | 40/40 | 20/60 | 100.0% | 33.3% | 66.7% | 0.50 s |
| Persistent + calibrated | 39/40 | 20/60 | 97.5% | 33.3% | 66.1% | 1.10 s |
| Budgeted + persistent | 0/40 | 0/60 | 0.0% | 0.0% | Undefined | N/A |

Approximate 95% Wilson intervals for calibration alone are 91.2–100.0% for
recall and 22.7–45.9% for FPR. These quantify run-level sampling uncertainty
under a binomial approximation; shared generator/environment and synthetic
controls limit real-world inference. They are not confidence intervals for the
paired performance difference.

## Why the original rule raised false alerts

The original combined rule flagged every held-out health check (6/6) and
every HTTPS monitoring heartbeat (3/3). It did not flag the HTTP heartbeats.
This identifies two different issues:

1. **Measurement scale:** connection bytes include TLS records and handshake
   overhead. In the original pilot, the held-out monitoring workload's median
   final size CV was about 0.229 for HTTP and 0.047 for HTTPS. A shared 0.06
   threshold treated these differently. Adding approximately constant overhead
   increases the mean without the same increase in standard deviation, lowering
   CV. This is a plausible mechanism supported by the measurements, not a
   separately randomized causal test of TLS overhead.
2. **Benign periodicity:** health checks are also regular and have stable sizes.
   They satisfy the same upper-bound rules as the synthetic channels. This
   does not prove that every possible model using these features must fail;
   it establishes a limitation of the tested rule family and workload design.

In the fresh study, development fitting selected request-size CV limits of
0.06 for HTTP and 0.01 for HTTPS, with a timing-CV limit of 0.35 for both.
Calibration removed all ten HTTPS monitoring false alerts, introduced no new
false alerts and lost no detections. That is 10 fewer false alerts, or 16.7
percentage points lower FPR, on the same held-out set. It is an observed
within-study improvement, not a promise of equivalent improvement elsewhere.

All 20 health-check test runs still triggered the calibrated rules. The
remaining 33.3% FPR is too high to describe these alerts as attack verdicts.

## Why the persistence variant was not better

The predeclared variant requires at least ten connections and three consecutive
qualifying cumulative prefixes. Its fitted thresholds matched calibration alone
in this study. It removed no further benign alerts and increased median detection
delay from 0.50 to 1.10 seconds, while missing one variable HTTPS channel run.

The missed run, `rd4d42fd6261d13d8`, crossed the 0.01 size-CV threshold at
prefixes 8 and 9, before the new ten-event gate. After that gate it qualified
only at prefixes 28 and 29; there was no third qualifying completed prefix
before the window ended. The earlier first-match rule detected it. The saved
features explain the difference without changing either model after testing.

The result does not show that persistence is universally ineffective. In this
study, false alerts were sustained benign behavior, so waiting for more similar
evidence did not remove them. Overlapping cumulative prefixes also are not
independent confirmations.

## What the false-positive budget tells us

The budgeted variant maximizes development recall subject to empirical FPR
at or below 10% for each transport. No useful candidate in the fixed grid met
that constraint, so both transports retained an explicit no-alert fallback.
Held-out recall was therefore zero. Precision is undefined, not 100%.

The constraint is an empirical development criterion, not a statistical or
operational guarantee. Even 0/18 development false alerts per transport has an
approximate 95% Wilson upper bound of 17.6%. It cannot certify an underlying
FPR below 10%. The fallback demonstrates insufficient separation for this rule
family; it is not a deployable low-noise detector.

## A second pitfall: apparent improvement through missing coverage

The development-only sensitivity audit of the old short pilot compares minimum
event counts 6, 10 and 14, and persistence counts 1 and 3. At higher gates,
some slower health checks become unscorable. A zero conditional FPR can then
appear because difficult benign cases left the denominator. The audit reports
positive and benign coverage separately to expose this effect. It does not
select a winning policy from the old or fresh held-out results.

## Refined baseline conclusion

> In a controlled HTTP/HTTPS study, the pooled timing-and-size baseline identified
> all 40 held-out simulated-channel runs but also flagged 30 of 60 benign runs.
> Transport-specific calibration reduced false alerts to 20 of 60 without losing
> detections. A later-gate/persistence variant offered no additional reduction and
> missed one positive run. Health checks remained a major source of false alerts,
> while imposing a 10% development-FPR cap eliminated useful recall within the
> evaluated rule family. These results support periodicity-based investigation
> leads and demonstrate the need for additional context and independent traffic
> validation before operational use.

At an assumed ratio of one positive to 50 benign windows, measured rates imply
approximately 3.8% precision for the pooled rule and 5.7% for calibration alone.
This assumes class-conditional rates transfer unchanged; it is not measured
production prevalence or production precision.

## What to build next

The next study should test whether independent context helps distinguish an
expected periodic service from an unexpected one. A manageable extension is a
small analyst workflow that combines a periodicity alert with a separately
maintained approved-service inventory and endpoint process evidence. Keep that
context independent of profile labels and measure its failure cases explicitly.
Approval or a familiar process name must not automatically prove traffic benign.

First collect independently authored benign clients over longer windows and a
second machine/day. Treat calibration alone as a candidate for that new study;
do not claim it has been validated by selecting it after viewing these results.
Do not remove health checks or use profile IDs as allowlists to improve scores.

The current release exports evidence in JSONL for a future SIEM adapter. Live
SIEM ingestion, passive PCAP/Zeek equivalence, production traffic, HTTP/2 and
connection pooling remain unvalidated. The shared build host was not an isolated
performance benchmark; scheduler/load effects remain part of the limitation.

## Reproduce and inspect

From the project root:

```sh
python -m unittest discover -s tests -v
python -u -m beaconlab run --config configs/refined_pilot.json --output runs/my-study
python -m beaconlab audit --run-dir runs/my-study --output runs/my-study-audit
```

- [Fresh study report](../examples/refined-pilot/report.html)
- [Fresh study results](../examples/refined-pilot/RESULTS.md)
- [Original baseline audit](../examples/baseline-audit/AUDIT.md)
- [Fresh study diagnostic audit](../examples/refined-audit/AUDIT.md)
- [Pre-collection protocol](refinement-protocol.md)
- [Verification record](../VERIFICATION.md)

New live executions may yield different timings and fitted thresholds. Saved
observations and frozen models support deterministic re-evaluation; seeded
workload plans alone do not guarantee identical network measurements.
