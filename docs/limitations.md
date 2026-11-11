# Limitations and next studies

BeaconLab v0.2 is a controlled synthetic traffic study. Its labels describe
workload purpose, and its results do not validate malware detection on a real
network. Current integration status is recorded in [VERIFICATION](../VERIFICATION.md).

## Dataset and measurement

The five generators are not representative of enterprise software. Success can
reflect chosen timing/size distributions. All clients share one HTTP library,
User-Agent and runtime. Shared fingerprints cannot establish software identity
or malicious intent; a legitimate unseen client can trigger a novelty alert.

The active TCP forwarder can perturb timing. Its byte counts include stream and
TLS overhead, not IP/link-layer headers. No passive PCAP/Zeek equivalence has
been demonstrated. The lab uses loopback, sequential workloads and one request
per connection. It does not model WAN latency, HTTP/2, connection pooling,
concurrent clients, session-resumption diversity or encrypted ClientHello.

The bounded JA3 parser supports a conventional visible ClientHello. Missing,
unrecognized or truncated data stays unavailable. JA3 maintenance and modern
client compatibility need review before any operational integration.

## Statistical interpretation

The current study has 60 development and 100 held-out runs. The original pilot
has 20 development and 30 test runs and is labeled historical in `examples/`.
Both are small samples from shared synthetic generators and a shared host.
Wilson intervals do not account for the full diversity of possible networks.

Thresholds are frozen before testing, but development selection can overfit.
Fresh seeds are new draws from the same generators, not independent application
families. A repeated-run, second-machine/day study has not been performed.

First-match evaluation counts transient alerts even if later data no longer
qualifies. Persistence uses overlapping prefixes and can increase delay or miss
short windows. A higher event gate may exclude slower benign workloads; inspect
class coverage alongside conditional FPR. Zero observed false positives is not
zero risk, and a no-alert policy has undefined precision and zero recall.

The 10% budget is an empirical development constraint, not an operational
service-level guarantee. Base-rate projections assume measured TPR/FPR transfer
unchanged; normalized alert rates from accelerated traffic are not forecasts.

## Next experiments

1. Collect independently authored benign clients over longer windows.
2. Repeat on another machine/day and distinguish input diversity from runtime noise.
3. Validate passive PCAP/Zeek observations against the active stream observer.
4. Test connection reuse under an explicitly revised observation model.
5. Evaluate independently maintained service/process context without using
   profile labels or ground truth as prediction inputs.
6. Validate a SIEM adapter using the structured JSONL evidence export.

Live SIEM ingestion and Windows/macOS execution remain unvalidated.
The export is an integration starting point; it is not evidence of a working
SIEM deployment. See [the findings](refinement-findings.md) for the measured
calibration improvement and the remaining health-check false alerts.
