# Architecture and data contract

## Components

| Module | Responsibility |
|---|---|
| traffic.py | Seeded, bounded workload schedules and actual loopback exchanges |
| network.py | Synthetic acknowledgement endpoint and transparent TCP observer |
| tls.py | Loopback certificates and bounded JA3 ClientHello parsing |
| features.py | Label-free observations and causal prefix features |
| models.py | Fixed rule families, development fitting, frozen prediction |
| metrics.py | Confusion counts, intervals, base-rate calculations |
| runner.py | Experiment orchestration, split order, provenance, freeze timestamp |
| evaluation.py | Held-out evaluation with overlap checks |
| report.py | HTML/Markdown output and optional scientific plots |
| diagnostics.py | False-positive traces, feature distributions, development-only sensitivity, structured alert evidence |
| capture.py | Optional actual tcpdump capture restricted to lab ports |
| zeek_import.py | Join Zeek JSON observations to known experiment windows |

## Flow

The generator sends synthetic messages through a local TCP observer to the
acknowledgement endpoint. For HTTPS, TLS terminates at the endpoint; the observer
sees encrypted records and the visible ClientHello, not plaintext HTTP headers.

The runner separately records labels and workload seeds in the manifest.
The observer writes connection records without labels. Feature extraction
uses only observations and window boundaries. The fitter can join development
labels; the evaluator joins test labels only after applying frozen rules.

## Observation fields

| Field | Meaning |
|---|---|
| ts | Observer's connection-start wall-clock timestamp |
| completed_ts | Observation completion timestamp |
| duration | Monotonic connection duration |
| orig_bytes / resp_bytes | Transferred TCP payload bytes in each direction |
| user_agent | Visible HTTP header, or null |
| ja3 / ja3_string | Parsed visible TLS ClientHello fingerprint, or null |
| transport | HTTP or HTTPS condition; stratification metadata |
| run_id | Opaque join key; not a numeric predictor |
| observer | Measurement provenance |
| error | Observation failure, or null |

The TCP observer counts application stream bytes. It cannot measure packet
retransmissions, packet loss, TCP flags, or link-layer headers. Those require
the optional packet capture workflow.

The runner uses one request per connection so connection arrivals correspond
to the generated exchanges in this first experiment. Persistent connections,
HTTP/2 multiplexing, and streaming protocols require a different feature model.

## Endpoints and bounds

The built-in endpoints bind to 127.0.0.1 and use dynamically allocated ports.
The client connects only to those loopback ports. The only accepted operation
is a bounded JSON exchange with sample and padding fields. There is no shell,
arbitrary task interpreter, file retrieval, persistence, or remote execution.

Run windows, request counts, message sizes, and socket timeouts are bounded.
TLS certificate verification remains enabled. Temporary private keys are
removed when the experiment exits; they are not needed to reproduce a report.

## Frozen model

The JSON model includes the candidate grids, selected thresholds, rule semantics,
development run IDs, and freeze timestamp. Fitting never reads held-out feature
records when computing its objective. Evaluation rejects overlap between
training IDs and test IDs.

The primary detector consumes only interval_cv and request_size_cv from causal
prefixes. The client-novelty baseline consumes an observed JA3 or User-Agent;
its benign reference set comes only from development data.

v0.2 adds optional `by_transport` rules. Transport chooses a separately fitted
threshold set; profile names never choose a threshold. Refined rules specify
their event gate and number of consecutive qualifying cumulative prefixes.
Insufficient observations return unavailable rather than a negative prediction.
Model hashes are checked during ordinary evaluation. New experiments record
analysis-source hashes and an immutable copy of the refinement protocol.

Audit outputs join profile labels only after decisions. `alerts.jsonl` contains
an evidence snapshot and the matching rule but no ground-truth class or profile.
It is a file export; no external SIEM connection is implemented.
