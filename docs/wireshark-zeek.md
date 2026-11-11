# Actual packet capture, Wireshark, and Zeek

The included studies use the TCP stream observer. This guide describes a separate
actual packet-capture path to run on your own local Linux lab. It was not
executed in the authoring environment because tcpdump/Zeek and capture privileges
were unavailable there.

## Collect a PCAP

Install tcpdump and Zeek using the supported packages for your operating system.
Use a lab account or VM with the appropriate local capture permission.
BeaconLab does not request privileges or install system software automatically.

From the project directory:

~~~sh
python -u -m beaconlab run --config configs/quickstart.json --output runs/pcap-pilot --pcap --interface lo
~~~

The conventional macOS loopback interface is **lo0**; macOS execution remains unvalidated. Capture is restricted to the two ephemeral
loopback observer ports recorded in the manifest. It does not capture arbitrary
traffic on the machine.

If capture fails to start, the command stops with an error. It never silently
labels stream observations as a packet capture.

Open **runs/pcap-pilot/capture.pcap** in Wireshark. Examine HTTP traffic and TLS
handshakes separately. The HTTP User-Agent is visible in cleartext traffic.
For HTTPS, it is not a plaintext network feature. The lab does not export TLS
session secrets or require decryption for this comparison.

## Generate Zeek JSON

Run Zeek in a clean directory. For example, from the project directory:

~~~sh
mkdir -p runs/pcap-pilot/zeek
cd runs/pcap-pilot/zeek
zeek -C -r ../capture.pcap LogAscii::use_json=T
cd ../../..
~~~

The **-C** option ignores checksum errors that can result from local checksum
offloading. JSON output is required by the importer. Connection UIDs join
conn.log to HTTP/TLS logs.

## Import and compare

~~~sh
python -m beaconlab import-zeek --logs runs/pcap-pilot/zeek --run-dir runs/pcap-pilot --output runs/pcap-pilot/zeek-observations
python -m beaconlab evaluate --run-dir runs/pcap-pilot --features runs/pcap-pilot/zeek-observations/features.jsonl --output runs/pcap-pilot/zeek-evaluation
~~~

This applies the already frozen stream-observer model to actual Zeek-derived
observations. Differences between sensors are part of the comparison; thresholds
are not silently refitted to improve the new result.

Inspect **import_report.json** for unmatched connections, invalid records, and
fingerprint availability. A JA3 field is not assumed to be built into every Zeek
installation: a compatible fingerprinting package may be needed. Without that
field, the HTTPS client-novelty baseline is unscored and its coverage is reduced.

The importer expects uncompressed, JSON-per-line Zeek logs. Capture timestamps
must share the experiment manifest's clock. The default lab uses the same host.
For a future multi-VM setup, document clock alignment before joining evidence.

Official references:

- [Zeek quickstart and JSON output](https://docs.zeek.org/en/current/quickstart.html)
- [Zeek common logs](https://docs.zeek.org/en/current/reference/logs/index.html)
- [Zeek TLS visibility](https://docs.zeek.org/en/current/reference/logs/ssl.html)
