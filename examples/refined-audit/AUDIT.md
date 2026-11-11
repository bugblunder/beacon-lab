# BeaconLab baseline and refinement audit

This is a retrospective diagnosis of saved observations. The original source files and frozen models are unchanged.

## Where false alerts occur

| Detector | Transport | Benign workload | False alerts / scored benign runs |
|---|---|---|---:|
| Timing | http | health_check | 10/10 |
| Timing | http | monitor_heartbeat | 10/10 |
| Timing | http | update_check | 0/10 |
| Timing | https | health_check | 10/10 |
| Timing | https | monitor_heartbeat | 10/10 |
| Timing | https | update_check | 0/10 |
| Timing + size | http | health_check | 10/10 |
| Timing + size | http | monitor_heartbeat | 0/10 |
| Timing + size | http | update_check | 0/10 |
| Timing + size | https | health_check | 10/10 |
| Timing + size | https | monitor_heartbeat | 10/10 |
| Timing + size | https | update_check | 0/10 |
| Client novelty | http | health_check | 0/10 |
| Client novelty | http | monitor_heartbeat | 0/10 |
| Client novelty | http | update_check | 0/10 |
| Client novelty | https | health_check | 0/10 |
| Client novelty | https | monitor_heartbeat | 0/10 |
| Client novelty | https | update_check | 0/10 |
| Transport calibrated | http | health_check | 10/10 |
| Transport calibrated | http | monitor_heartbeat | 0/10 |
| Transport calibrated | http | update_check | 0/10 |
| Transport calibrated | https | health_check | 10/10 |
| Transport calibrated | https | monitor_heartbeat | 0/10 |
| Transport calibrated | https | update_check | 0/10 |
| Persistent + calibrated | http | health_check | 10/10 |
| Persistent + calibrated | http | monitor_heartbeat | 0/10 |
| Persistent + calibrated | http | update_check | 0/10 |
| Persistent + calibrated | https | health_check | 10/10 |
| Persistent + calibrated | https | monitor_heartbeat | 0/10 |
| Persistent + calibrated | https | update_check | 0/10 |
| Budgeted + persistent | http | health_check | 0/10 |
| Budgeted + persistent | http | monitor_heartbeat | 0/10 |
| Budgeted + persistent | http | update_check | 0/10 |
| Budgeted + persistent | https | health_check | 0/10 |
| Budgeted + persistent | https | monitor_heartbeat | 0/10 |
| Budgeted + persistent | https | update_check | 0/10 |

## Measurement-scale diagnosis

Connection byte counts include protocol overhead. CV = standard deviation / mean, so adding roughly constant bytes reduces CV. HTTP and HTTPS thresholds therefore need explicit evaluation; these observational differences do not isolate a causal effect of TLS.

| Held-out workload | Transport | Median timing CV | Median size CV | Median mean originator bytes |
|---|---|---:|---:|---:|
| channel_regular | http | 0.0288 | 0.0249 | 376.4 |
| channel_variable | http | 0.2642 | 0.0479 | 394.4 |
| health_check | http | 0.0176 | 0.0242 | 377.7 |
| monitor_heartbeat | http | 0.1764 | 0.2069 | 524.0 |
| update_check | http | 1.0869 | 0.2565 | 690.2 |
| channel_regular | https | 0.0295 | 0.0047 | 1998.6 |
| channel_variable | https | 0.2650 | 0.0089 | 2014.4 |
| health_check | https | 0.0178 | 0.0043 | 1998.6 |
| monitor_heartbeat | https | 0.1836 | 0.0549 | 2158.4 |
| update_check | https | 1.0531 | 0.0773 | 2305.4 |

![Held-out feature distributions](figures/feature_overlap.png)


## Development-only gate sensitivity

Each cell refits the same fixed grid on development runs only. These are in-sample diagnostics; they must not be reported as held-out performance or used to retrospectively select a winning test result. Missing cells mean inadequate available evidence.

Raising the minimum can exclude slow benign clients entirely. A lower conditional FPR with lower benign coverage does not establish better detection.

| Transport | Minimum events | Consecutive prefixes | Dev TPR | Dev FPR | Positive coverage | Benign coverage | Median delay (s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| http | 6 | 1 | 100.0% | 33.3% | 100.0% | 100.0% | 0.50 |
| http | 6 | 3 | 100.0% | 33.3% | 100.0% | 100.0% | 0.70 |
| http | 10 | 1 | 100.0% | 33.3% | 100.0% | 100.0% | 0.90 |
| http | 10 | 3 | 100.0% | 33.3% | 100.0% | 100.0% | 1.09 |
| http | 14 | 1 | 100.0% | 33.3% | 100.0% | 100.0% | 1.30 |
| http | 14 | 3 | 100.0% | 33.3% | 100.0% | 100.0% | 1.51 |
| https | 6 | 1 | 100.0% | 33.3% | 100.0% | 100.0% | 0.50 |
| https | 6 | 3 | 100.0% | 33.3% | 100.0% | 100.0% | 0.70 |
| https | 10 | 1 | 100.0% | 33.3% | 100.0% | 100.0% | 0.90 |
| https | 10 | 3 | 100.0% | 33.3% | 100.0% | 100.0% | 1.10 |
| https | 14 | 1 | 100.0% | 33.3% | 100.0% | 100.0% | 1.30 |
| https | 14 | 3 | 100.0% | 33.3% | 100.0% | 100.0% | 1.50 |

## How to read this evidence

- 1 pooled timing-plus-size false alerts no longer matched at the final prefix. They still count as false alerts; later data cannot erase an emitted alert.
- Consecutive cumulative prefixes overlap. Persistence can suppress transient triggers but is not independent confirmation or a solution to sustained benign periodicity.
- `false_positive_cases.csv` traces each benign alert to the exact threshold and causal prefix.
- `alerts.jsonl` provides structured, label-free evidence for a future SIEM adapter. No SIEM ingestion has been performed.
- Class/profile information is joined only for evaluation. It is not an input to prediction.
- Review RESULTS.md/report.html for held-out metrics, uncertainty, paired changes and conclusions.
