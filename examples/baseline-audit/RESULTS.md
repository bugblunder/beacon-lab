# BeaconLab experiment results

**Synthetic lab traffic; pilot evidence, not production validation.**

Actual loopback HTTP/S traffic was observed by an active transparent TCP forwarder. These are socket-level stream observations, not passive packet captures. Byte counts include TCP payload and TLS records, not TCP/IP headers. No PCAP was captured for this experiment.

Development runs: 20. Held-out runs: 30.
Observer: tcp_stream_proxy. Failed runs excluded: 0.

| Detector | Transport | Scored/total | TP/FN | FP/TN | TPR | FPR | Precision |
|---|---|---:|---:|---:|---:|---:|---:|
| Timing | all | 30/30 | 12/0 | 12/6 | 100.0% | 66.7% | 50.0% |
| Timing | http | 15/15 | 6/0 | 6/3 | 100.0% | 66.7% | 50.0% |
| Timing | https | 15/15 | 6/0 | 6/3 | 100.0% | 66.7% | 50.0% |
| Timing + size | all | 30/30 | 12/0 | 9/9 | 100.0% | 50.0% | 57.1% |
| Timing + size | http | 15/15 | 6/0 | 3/6 | 100.0% | 33.3% | 66.7% |
| Timing + size | https | 15/15 | 6/0 | 6/3 | 100.0% | 66.7% | 50.0% |
| Client novelty | all | 30/30 | 0/12 | 0/18 | 0.0% | 0.0% | N/A |
| Client novelty | http | 15/15 | 0/6 | 0/9 | 0.0% | 0.0% | N/A |
| Client novelty | https | 15/15 | 0/6 | 0/9 | 0.0% | 0.0% | N/A |

## Conclusions

- The pooled timing-plus-size baseline detected 12/12 scored positive runs and alerted on 9/18 scored benign runs (FPR 50.0%). Its label is a synthetic workload, not an attack verdict.
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

The HTML report includes confidence intervals, profile results, and an interactive base-rate calculation.
