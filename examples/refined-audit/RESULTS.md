# BeaconLab experiment results

**Synthetic lab traffic; pilot evidence, not production validation.**

Actual loopback HTTP/S traffic was observed by an active transparent TCP forwarder. These are socket-level stream observations, not passive packet captures. Byte counts include TCP payload and TLS records, not TCP/IP headers. No PCAP was captured for this experiment.

Development runs: 60. Held-out runs: 100.
Observer: tcp_stream_proxy. Failed runs excluded: 0.

| Detector | Transport | Scored/total | TP/FN | FP/TN | TPR | FPR | Precision |
|---|---|---:|---:|---:|---:|---:|---:|
| Timing | all | 100/100 | 40/0 | 40/20 | 100.0% | 66.7% | 50.0% |
| Timing | http | 50/50 | 20/0 | 20/10 | 100.0% | 66.7% | 50.0% |
| Timing | https | 50/50 | 20/0 | 20/10 | 100.0% | 66.7% | 50.0% |
| Timing + size | all | 100/100 | 40/0 | 30/30 | 100.0% | 50.0% | 57.1% |
| Timing + size | http | 50/50 | 20/0 | 10/20 | 100.0% | 33.3% | 66.7% |
| Timing + size | https | 50/50 | 20/0 | 20/10 | 100.0% | 66.7% | 50.0% |
| Client novelty | all | 100/100 | 0/40 | 0/60 | 0.0% | 0.0% | N/A |
| Client novelty | http | 50/50 | 0/20 | 0/30 | 0.0% | 0.0% | N/A |
| Client novelty | https | 50/50 | 0/20 | 0/30 | 0.0% | 0.0% | N/A |
| Transport calibrated | all | 100/100 | 40/0 | 20/40 | 100.0% | 33.3% | 66.7% |
| Transport calibrated | http | 50/50 | 20/0 | 10/20 | 100.0% | 33.3% | 66.7% |
| Transport calibrated | https | 50/50 | 20/0 | 10/20 | 100.0% | 33.3% | 66.7% |
| Persistent + calibrated | all | 100/100 | 39/1 | 20/40 | 97.5% | 33.3% | 66.1% |
| Persistent + calibrated | http | 50/50 | 20/0 | 10/20 | 100.0% | 33.3% | 66.7% |
| Persistent + calibrated | https | 50/50 | 19/1 | 10/20 | 95.0% | 33.3% | 65.5% |
| Budgeted + persistent | all | 100/100 | 0/40 | 0/60 | 0.0% | 0.0% | N/A |
| Budgeted + persistent | http | 50/50 | 0/20 | 0/30 | 0.0% | 0.0% | N/A |
| Budgeted + persistent | https | 50/50 | 0/20 | 0/30 | 0.0% | 0.0% | N/A |

## Conclusions

- The pooled timing-plus-size baseline detected 40/40 scored positive runs and alerted on 30/60 scored benign runs (FPR 50.0%). Its label is a synthetic workload, not an attack verdict.
- Transport calibration alone detected 40/40 scored positives and produced 20/60 false alerts on the same held-out set, with 100.0% scoring coverage.
- On the same held-out runs, the persistent, transport-calibrated rule detected 39/40 scored positives and alerted on 20/60 scored benign runs. Positive coverage was 100.0%; benign coverage was 100.0%.
- The later-gate/persistence variant removed no additional false alerts versus calibration alone. It detected 39 versus 40 positives; median detection delay was 1.10 versus 0.50 seconds.
- Remaining false alerts include health_check. Periodicity and size variation alone still overlap with benign behavior.
- The 10.0% development-FPR budget produced held-out recall 0.0% and FPR 0.0%. It emitted no alerts: precision is undefined, and zero alerts do not demonstrate useful detection.
- Fresh seeds test new draws from the same generator. These findings support investigation of periodic traffic, not operational malware-detection claims.

## Limitations

- Labels describe synthetic workload purpose, not observed malicious intent.
- Reported rates are conditional on detector availability; coverage is reported separately.
- Wilson intervals are approximate per-run binomial intervals, not guarantees of real-network generalization.
- Prevalence-adjusted precision is hypothetical and assumes measured TPR/FPR transfer unchanged.
- Benign-hour alert rates from accelerated pilot traffic are not production alert-volume forecasts.
- The first qualifying prefix emits at most one alert per run; thresholds remain frozen.
- Original baselines use the configured minimum-event gate. Refinement policies, when present, carry explicit gates and persistence; client novelty does not use them.
- Client novelty means an observed UA/JA3 was absent from benign development signals; it can flag legitimate population changes and does not establish maliciousness.
- Repeated config/seed inputs are deterministic only with fixed generator code/runtime; measured traffic, fitted rules, and results may vary between live executions.
- Transport calibration and persistence were chosen after reviewing the earlier pilot, then evaluated on fresh runs. This remains the same synthetic generator family.
- The false-positive budget constrains development observations only. Report held-out misses and uncertainty even when no alerts occur.
- Consecutive cumulative prefixes overlap; persistence is a debounce policy, not independent statistical confirmation.

The HTML report includes confidence intervals, profile results, and an interactive base-rate calculation.
