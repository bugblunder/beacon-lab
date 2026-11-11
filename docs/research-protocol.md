# Research method — v0.2

The question is whether simple network rules distinguish simulated channel
traffic from benign periodic clients. A positive label describes the workload
generator, not malicious intent. The unit is one fixed-duration
client–destination run, not an individual packet.

## Controls and observation

| Profile | Experimental class |
|---|---|
| `channel_regular` | Simulated channel |
| `channel_variable` | Simulated channel |
| `health_check` | Benign periodic health check |
| `monitor_heartbeat` | Benign monitoring heartbeat |
| `update_check` | Benign bursty update checker |

All profiles share the Python HTTP library, User-Agent, endpoint and message
schema. They receive the same acknowledgement. Profile names, labels and seeds
are not transmitted or used as prediction features.

Actual loopback HTTP/HTTPS exchanges cross an active TCP forwarder. It measures
connection timing and transferred TCP payload bytes, including TLS records for
HTTPS; it does not decrypt HTTPS or capture packets. Each request opens a new
connection. Runs execute sequentially within one shared runtime.

## Freeze before test collection

1. Validate the configuration and persist the seeded run plan.
2. Assign disjoint seeds and randomize order within each split.
3. Collect development runs and fit only on their labels and observations.
4. Save all rules, training IDs, freeze timestamp and model hash.
5. Collect fresh held-out runs, then score them without refitting.

The v0.2 study uses 60 development and 100 held-out runs, across both transports
and all five profiles. Each window is three seconds with a 0.10-second base
interval. These accelerated rates are not models of production activity.

The original pilot motivated the refinements; it is exploratory evidence for
this design. The [prospective protocol](refinement-protocol.md) was fixed before
the fresh study, and its exact copy/hash is retained with that study.

## Six frozen policies

| Policy | Fitting and decision rule |
|---|---|
| Timing | Pooled interval-CV threshold; first match after six events |
| Timing + size | Pooled interval-CV and size-CV thresholds; same gate |
| Client novelty | UA/JA3 absent from benign development signals |
| Transport calibrated | Separate HTTP/HTTPS timing-and-size thresholds; six-event gate |
| Persistent + calibrated | Separate thresholds; ten-event gate and three consecutive matching prefixes |
| Budgeted + persistent | Same gate/persistence; maximize development recall under a 10% empirical FPR cap per transport |

Non-budgeted numeric policies maximize development balanced accuracy, breaking
ties toward lower FPR. The budgeted policy has an explicit no-alert fallback.
The candidate grids are fixed in `beaconlab/models.py`. A development FPR cap is
not a guaranteed future FPR, and a no-alert fallback has no useful recall.

Each decision uses only completed observations available at that moment.
At most one alert occurs per detector/run, and later evidence cannot erase an
earlier alert. Consecutive cumulative prefixes overlap; they are not independent
confirmations. Insufficient evidence is unavailable, not a negative prediction.

Numeric inputs are timing CV and originator-byte CV. Transport may select
thresholds. IP addresses, ports, labels, profile names, payload markers and
absolute timestamps are excluded from prediction. UA/JA3 novelty measures an
unseen client signal; it does not prove an attacker is present.

## Evaluation and diagnostics

Report TP/FN/FP/TN, recall, FPR, precision, class coverage and detection delay.
Rates are conditional on scoring availability. Precision is undefined when no
alerts occur. Approximate Wilson intervals describe run-level uncertainty;
shared generators and environment limit independence and external validity.
Paired comparisons count alerts removed/added and detections lost/gained on the
same test runs. They do not compare different studies as if conditions matched.

The audit's sensitivity grid uses development data only: 6, 10 and 14 events,
and one or three consecutive prefixes. It reports positive and benign coverage
so removing slow benign clients from scoring cannot masquerade as improvement.
It neither selects a winning held-out configuration nor changes the frozen model.

For an explicitly assumed prevalence p:

```text
precision = (TPR * p) / (TPR * p + FPR * (1 - p))
```

This projection assumes unchanged class-conditional rates. It does not establish
real-network prevalence or operational alert volume. Benign-client-hour rates
from accelerated windows are normalized measurements, not production forecasts.

## Reproducibility boundary

For fixed generator code/runtime, seeded plans, order, IDs, schedules and message
inputs are repeatable. Network timing, TLS randomness, observed features and
fitted results may differ on a new live execution. Replaying saved observations
with the same model is a separate, deterministic check.

New experiments record plan, generator, analysis-source and model hashes, and
a protocol hash when the refinement protocol is available. The original pilot
predates some fields; they were not retroactively fabricated. Historical details
are in the [v0.1.1 review](history/review-v0.1.1.md).

See [the measured findings](refinement-findings.md), [limitations](limitations.md),
and [verification record](../VERIFICATION.md) before making claims beyond this lab.
