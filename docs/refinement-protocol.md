# BeaconLab v0.2 prospective refinement protocol

This design is fixed before the fresh study is collected. The runner copies this
file and records its hash, configuration hash, analysis-source hashes and the
model freeze timestamp. The original v0.1 pilot is exploratory evidence for this
design; it is not a second untouched test set for these refinements.

## Research question

Do transport-specific size thresholds and sustained evidence reduce false alerts
relative to pooled timing-plus-size thresholds, on the same fresh held-out runs?
What recall remains when an empirical development false-positive budget is imposed?

## Motivation from the original pilot

The combined rule flagged all six health-check test runs and all three HTTPS
monitoring runs. Health-check timing/size distributions overlap with the synthetic
channels. HTTPS connections include TLS overhead, changing the scale of byte CV.
If a roughly constant overhead C is added to each size X, CV(X+C) is
std(X)/(mean(X)+C). This suggests a measurement-scale issue, not evidence that
encryption makes a client malicious. This experiment does not isolate TLS
overhead in a randomized causal intervention.

## Fixed comparisons

1. Timing: original pooled grid, six-event minimum, first qualifying prefix.
2. Timing + size: original pooled grid and selection objective, same gate.
3. Client novelty: original benign-development UA/JA3 reference.
4. Transport calibrated: timing + size fitted separately for HTTP/HTTPS, six-event
   minimum and first qualifying prefix. This is the calibration ablation.
5. Persistent + calibrated (primary refinement): separate transport thresholds,
   ten-event minimum, three consecutive qualifying cumulative prefixes.
6. Budgeted + persistent: same gate and transport policy as 5, maximize development
   recall subject to empirical development FPR <= 10% per transport. Ties favor
   lower FPR; if no useful candidate qualifies, retain an explicit no-alert policy.

Policies 1, 2, 4 and 5 maximize development balanced accuracy, with ties favoring
lower FPR. All use the existing fixed grids, two numeric CV features and no
workload labels, profiles, seeds, IPs or payload markers at prediction time.
The primary persistence policy has not been chosen by searching the old test set.
Ten events and three prefixes are engineering choices to test, not proven optima.
Three overlapping prefixes are not three independent pieces of evidence.

## Collection and analysis

Use configs/refined_pilot.json: fresh seed 9384721, five unchanged profiles, both
transports, six development repetitions and ten test repetitions per cell.
This produces 60 development and 100 test runs. Windows last three seconds with
0.10-second base intervals. Inputs are synthetic and accelerated. Development
is collected first; all six models are frozen before held-out collection.
The feature extractor retains prefixes starting at six events; each refined rule
enforces its own later gate. No profile is removed to improve reported FPR.

Compare policies on the same held-out set. Report counts, coverage by class,
TPR/FPR with approximate Wilson intervals, precision, detection delay, profile
breakdowns, and paired alert changes. A lower FPR achieved by losing recall must
be visible. Zero-alert precision is undefined. A development FPR cap is not a
held-out guarantee or a production service-level objective.

A separate development-only sensitivity table compares six, ten and fourteen
events and one versus three consecutive prefixes. It does not choose a winner,
refit the frozen model, or run a threshold sweep on the fresh test set.
Do not revise the primary policy after seeing held-out results. Any further
change needs a new named study and fresh hold-out data. Preserve failed runs.

## Interpretation

Fresh seeds improve within-generator evaluation, not independent software or
network diversity. The original pilot and new study differ in seed, window length,
interval and environment; compare models within the new study for improvement
claims. A before/after percentage from different studies is descriptive only.

Periodic network behavior is an investigation lead, not proof of C2 or malicious
intent. If health checks remain indistinguishable, the next substantive change
needs independent context (such as approved service inventory or endpoint process
lineage), tested without allowing profile names or ground truth into scoring.

## References

- MITRE ATT&CK T1071.001: https://attack.mitre.org/techniques/T1071/001/
- Zeek conn.log measurement fields: https://docs.zeek.org/en/current/reference/logs/conn.html
- NIST Wilson interval method: https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm
