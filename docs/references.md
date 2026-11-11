# References and research context

- MITRE ATT&CK, [T1071.001: Web Protocols](https://attack.mitre.org/techniques/T1071/001/).
  The simulated communication illustrates the protocol category; it does not
  demonstrate an intrusion or infer intent from the protocol alone.
- MITRE ATT&CK, [DET0027: Web protocol C2 detection](https://attack.mitre.org/detectionstrategies/DET0027/).
- Zeek, [Quick Start Guide](https://docs.zeek.org/en/current/quickstart.html) and
  [TLS logging](https://docs.zeek.org/en/current/reference/logs/ssl.html).
- Salesforce Engineering, [TLS fingerprinting with JA3 and JA3S](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/).
- Salesforce, [original JA3 algorithm and repository](https://github.com/salesforce/ja3).
  The original repository notes that it is no longer actively maintained by
  Salesforce. BeaconLab's small parser is for this controlled experiment.
- Elastic Security Labs, [Identifying beaconing malware using Elastic](https://security-labs.elastic.co/security-labs/identifying-beaconing-malware-using-elastic).
  Periodicity can also occur in legitimate software.
- Stefan Axelsson, [The Base-Rate Fallacy and the Difficulty of Intrusion Detection](https://people.scs.carleton.ca/~soma/id/readings/axelsson-base-rate.pdf),
  ACM Transactions on Information and System Security, 2000.
- IETF, [RFC 5905: NTPv4](https://www.rfc-editor.org/rfc/rfc5905.html).

The research contribution of a completed study would be its reproducible
dataset, explicit controls, measured results, and analysis of limitations.
This repository does not claim that periodicity analysis or C2 simulation is novel.
