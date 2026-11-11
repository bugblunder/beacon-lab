"""Portable HTML/Markdown reports and optional standard scientific plots."""
from __future__ import annotations

import html
import json
from pathlib import Path

from . import __version__

DISPLAY = {
    "timing": "Timing",
    "timing_and_size": "Timing + size",
    "client_novelty": "Client novelty",
    "transport_calibrated": "Transport calibrated",
    "persistent_calibrated": "Persistent + calibrated",
    "budgeted_persistent": "Budgeted + persistent",
}


def pct(value):
    return "N/A" if value is None else f"{100 * value:.1f}%"


def number(value):
    return "N/A" if value is None else f"{value:.2f}"


def interval(value):
    return "N/A" if value is None else f"{100 * value[0]:.1f}–{100 * value[1]:.1f}%"


def plots(output: Path, summary: dict) -> list[str]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return []
    folder = output / "figures"
    folder.mkdir(exist_ok=True)
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "figure.facecolor": "white", "axes.facecolor": "white"})
    groups = [row for row in summary["groups"] if row["transport"] == "all"]
    labels = [DISPLAY[row["detector"]] for row in groups]
    colors = ["#126d78" if row["detector"] == "persistent_calibrated" else "#627788" for row in groups]
    fig, axes = plt.subplots(1, 2, figsize=(12, max(4.6, .65 * len(groups) + 1.3)), layout="constrained")
    for axis, key, title in zip(axes, ("tpr", "fpr"), ("True-positive rate", "False-positive rate")):
        values = [100 * row[key] if row[key] is not None else 0 for row in groups]
        axis.barh(range(len(groups)), values, color=colors, height=0.65)
        for x, row in enumerate(groups):
            if row[key] is None:
                axis.text(3, x, "N/A", va="center", fontsize=9)
                continue
            ci = row[key + "_ci95"]
            axis.errorbar(values[x], x, xerr=[[max(0, values[x] - 100 * ci[0])],
                                             [max(0, 100 * ci[1] - values[x])]],
                          fmt="none", color="#192633", capsize=3, linewidth=1)
        axis.set_yticks(range(len(groups)), labels, fontsize=9)
        axis.invert_yaxis()
        axis.set_xlim(0, 110)
        axis.set_xlabel("Percent")
        axis.set_title(title, loc="left", fontweight="bold")
        axis.grid(axis="x", alpha=0.15)
        axis.set_axisbelow(True)
    fig.suptitle("Held-out synthetic workload detection · approximate 95% Wilson intervals",
                 fontsize=13)
    fig.savefig(folder / "detection_rates.png", dpi=170)
    fig.savefig(folder / "detection_rates.svg")
    plt.close(fig)

    fig, axis = plt.subplots(figsize=(8.5, 4.4), layout="constrained")
    for row in summary["groups"]:
        if row["transport"] != "all":
            continue
        scenarios = [s for s in row["prevalence_scenarios"] if s["adjusted_precision"] is not None]
        if scenarios:
            axis.plot([100 * s["assumed_prevalence"] for s in scenarios],
                      [100 * s["adjusted_precision"] for s in scenarios], "o-",
                      label=DISPLAY[row["detector"]], linewidth=2)
    axis.set_xscale("log")
    axis.set_ylim(0, 105)
    axis.set_xlabel("Assumed simulated-channel prevalence (%) · log scale")
    axis.set_ylabel("Hypothetical precision (%)")
    axis.set_title("Base-rate sensitivity, assuming measured TPR and FPR transfer unchanged",
                   loc="left", fontsize=11)
    axis.grid(alpha=0.2)
    handles, _ = axis.get_legend_handles_labels()
    if handles:
        axis.legend(frameon=False)
    fig.savefig(folder / "base_rate.png", dpi=170)
    fig.savefig(folder / "base_rate.svg")
    plt.close(fig)
    return ["figures/detection_rates.png", "figures/base_rate.png"]


def conclusions(summary: dict) -> list[str]:
    """Describe the observed trade-off; never turn a no-alert rule into a win."""
    groups = {row["detector"]: row for row in summary["groups"] if row["transport"] == "all"}
    notes = []
    baseline = groups.get("timing_and_size")
    if baseline:
        notes.append(f"The pooled timing-plus-size baseline detected {baseline['tp']}/{baseline['tp'] + baseline['fn']} "
                     f"scored positive runs and alerted on {baseline['fp']}/{baseline['fp'] + baseline['tn']} "
                     f"scored benign runs (FPR {pct(baseline['fpr'])}). Its label is a synthetic workload, not an attack verdict.")
    refined = groups.get("persistent_calibrated")
    calibrated = groups.get("transport_calibrated")
    if calibrated:
        notes.append(f"Transport calibration alone detected {calibrated['tp']}/{calibrated['tp'] + calibrated['fn']} "
                     f"scored positives and produced {calibrated['fp']}/{calibrated['fp'] + calibrated['tn']} false alerts "
                     f"on the same held-out set, with {pct(calibrated['coverage'])} scoring coverage.")
    if refined:
        notes.append(f"On the same held-out runs, the persistent, transport-calibrated rule detected "
                     f"{refined['tp']}/{refined['tp'] + refined['fn']} scored positives and alerted on "
                     f"{refined['fp']}/{refined['fp'] + refined['tn']} scored benign runs. "
                     f"Positive coverage was {pct(refined['positive_coverage'])}; benign coverage was {pct(refined['benign_coverage'])}.")
        if calibrated and refined["coverage"] == calibrated["coverage"] == 1:
            if refined["fp"] == calibrated["fp"]:
                notes.append(f"The later-gate/persistence variant removed no additional false alerts versus calibration alone. "
                             f"It detected {refined['tp']} versus {calibrated['tp']} positives; median detection delay was "
                             f"{number(refined['median_detection_seconds'])} versus {number(calibrated['median_detection_seconds'])} seconds.")
        failures = [row for row in summary["profile_groups"]
                    if row["detector"] == "persistent_calibrated" and row["fp"]]
        if failures:
            names = ", ".join(sorted({row["profile"] for row in failures}))
            notes.append(f"Remaining false alerts include {names}. Periodicity and size variation alone still overlap with benign behavior.")
    budgeted = groups.get("budgeted_persistent")
    if budgeted:
        cap = summary["refinement"]["max_development_fpr"]
        notes.append(f"The {pct(cap)} development-FPR budget produced held-out recall {pct(budgeted['tpr'])} "
                     f"and FPR {pct(budgeted['fpr'])}. " +
                     ("It emitted no alerts: precision is undefined, and zero alerts do not demonstrate useful detection."
                      if budgeted["tp"] + budgeted["fp"] == 0 else
                      "The development cap is not a guarantee on future traffic; assess missed positives and the FPR interval."))
    notes.append("Fresh seeds test new draws from the same generator. These findings support investigation of periodic traffic, not operational malware-detection claims.")
    return notes


def create_report(output: Path, manifest: dict, model: dict, summary: dict, *, charts=True):
    output.mkdir(parents=True, exist_ok=True)
    images = plots(output, summary) if charts else []
    all_groups = [row for row in summary["groups"] if row["transport"] == "all"]
    connections = sum(run.get("observed_total_connections", 0) for run in manifest["runs"])
    primary = ", ".join(summary["observer"])
    is_proxy = "tcp_stream_proxy" in summary["observer"]
    provenance = (
        "Actual loopback HTTP/S traffic was observed by an active transparent TCP forwarder. "
        "These are socket-level stream observations, not passive packet captures. Byte counts "
        "include TCP payload and TLS records, not TCP/IP headers."
        if is_proxy else
        "Features were imported from Zeek JSON logs associated with the experiment's recorded "
        "time windows and observer ports. Packet-capture loss and unavailable fields affect coverage."
    )
    raw_capture = manifest["measurement"].get("raw_packet_capture_performed", False)
    provenance += (" An additional PCAP was captured during this experiment."
                   if raw_capture else " No PCAP was captured for this experiment.")
    totals = []
    for row in summary["groups"]:
        if row["transport"] == "all":
            continue
        totals.append("<tr>" + "".join("<td>" + html.escape(str(value)) + "</td>" for value in (
            DISPLAY[row["detector"]], row["transport"].upper(),
            f"{row['n_scored']}/{row['n_total']}",
            f"{row['tp']} / {row['fn']}", f"{row['fp']} / {row['tn']}",
            pct(row["tpr"]), pct(row["fpr"]), pct(row["precision"]),
            number(row["median_detection_seconds"]))) + "</tr>")
    uncertainty = []
    for row in all_groups:
        uncertainty.append("<tr>" + "".join("<td>" + html.escape(str(value)) + "</td>" for value in (
            DISPLAY[row["detector"]], interval(row["tpr_ci95"]), interval(row["fpr_ci95"]),
            number(row["false_alerts_per_benign_client_hour"]),
            pct(row["prevalence_scenarios"][2]["adjusted_precision"]))) + "</tr>")
    profile_rows = []
    for row in summary["profile_groups"]:
        if row["detector"] not in {"timing_and_size", "persistent_calibrated", "budgeted_persistent"}:
            continue
        is_positive = row["profile"].startswith("channel_")
        rate = row["tpr"] if is_positive else row["fpr"]
        profile_rows.append("<tr>" + "".join("<td>" + html.escape(str(value)) + "</td>" for value in (
            DISPLAY[row["detector"]], row["profile"], row["transport"].upper(), "simulated channel" if is_positive else "benign",
            f"{row['n_scored']}/{row['n_total']}", pct(rate))) + "</tr>")
    figure_html = "".join('<figure><img alt="Research evaluation chart" src="' + name + '"></figure>'
                          for name in images)
    notes = "".join("<li>" + html.escape(note) + "</li>" for note in summary["notes"])
    findings = conclusions(summary)
    finding_html = "".join("<p>" + html.escape(note) + "</p>" for note in findings)
    paired_rows = "".join("<tr>" + "".join("<td>" + html.escape(str(value)) + "</td>" for value in (
        DISPLAY[row["candidate"]], row["n_jointly_scored"], row["benign_alerts_removed"],
        row["benign_alerts_added"], row["positive_detections_lost"], row["positive_detections_gained"])) + "</tr>"
        for row in summary.get("paired_comparisons", []))
    paired_html = ("<section><h2>Paired changes versus pooled timing + size</h2><div class='scroll'><table>"
                   "<thead><tr><th>Candidate</th><th>Jointly scored</th><th>Benign alerts removed</th>"
                   "<th>Benign alerts added</th><th>Positive detections lost</th><th>Positive detections gained</th>"
                   "</tr></thead><tbody>" + paired_rows + "</tbody></table></div>"
                   "<p class='muted'>All differences use the same held-out runs. Unavailable pairs are excluded; review coverage.</p></section>"
                   if paired_rows else "")
    options = "".join('<option value="' + str(i) + '">' + html.escape(DISPLAY[row["detector"]]) + "</option>"
                      for i, row in enumerate(all_groups))
    json_data = json.dumps([{"name": DISPLAY[row["detector"]], "tpr": row["tpr"], "fpr": row["fpr"]}
                            for row in all_groups]).replace("<", "\\u003c")
    page = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BeaconLab · Detection research report</title>
<style>
:root{--ink:#172b39;--muted:#526673;--teal:#126d78;--line:#dbe4e8;--paper:#f3f6f7}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.65 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1160px;margin:auto;padding:46px 24px 70px}header{border-top:5px solid var(--teal);padding:26px 0 20px}
.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:.16em;font-weight:750;color:var(--teal)}
h1{font-size:clamp(30px,4vw,48px);line-height:1.12;margin:14px 0}h2{font-size:22px;margin:0 0 14px}h3{font-size:17px}
p{margin:10px 0}.muted{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:20px 0}
.card,section{background:#fff;border:1px solid var(--line);border-radius:12px;padding:22px}.card strong{display:block;font-size:30px;line-height:1.3}.card span{font-size:12px;color:var(--muted)}
section{margin:18px 0}.notice{border-left:4px solid #b17925;background:#fff9ef;padding:16px 20px;border-radius:6px}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th{text-align:left;color:var(--muted);font-weight:650;background:#f4f7f8}
th,td{padding:11px 12px;border-bottom:1px solid var(--line);vertical-align:top}td{white-space:nowrap}
figure{margin:18px 0}img{display:block;max-width:100%;height:auto;border-radius:6px}
pre{overflow:auto;font-size:12px;line-height:1.5;background:#f4f7f8;padding:18px;border-radius:6px}
label{display:block;font-size:13px;margin:8px 0}select,input{font:inherit;padding:9px;border:1px solid #b9c8cf;border-radius:6px;max-width:100%}
.calculator{display:grid;grid-template-columns:1fr 1fr 1.5fr;gap:20px;align-items:center}.result{background:#edf7f6;padding:18px;border-radius:8px}.result strong{font-size:27px;display:block}
code{font-size:.92em}a{color:var(--teal)}ul{padding-left:22px}footer{font-size:12px;color:var(--muted)}
@media(max-width:700px){main{padding:22px 14px}.cards{grid-template-columns:1fr 1fr}.calculator{grid-template-columns:1fr}section{padding:16px}}
</style></head><body><main>
<header><div class="eyebrow">BeaconLab / controlled experiment</div>
<h1>What do simple network rules<br>actually distinguish?</h1>
<p class="muted">A reproducible pilot comparing synthetic channel traffic with benign periodic HTTP/S clients.</p></header>
<div class="notice"><strong>Interpretation boundary.</strong> All traffic is generated in a local lab. A positive label
means a simulated channel profile, not malicious intent. Short pilot windows and shared client libraries limit generalization.</div>
<div class="cards">
<div class="card"><strong>@@DEV@@</strong><span>development runs</span></div>
<div class="card"><strong>@@TEST@@</strong><span>held-out runs</span></div>
<div class="card"><strong>@@CONNECTIONS@@</strong><span>stream-observer connections · all runs</span></div>
<div class="card"><strong>@@DETECTORS@@</strong><span>frozen detector policies</span></div>
</div>
<section><h2>What this experiment establishes</h2>@@FINDINGS@@</section>
<section><h2>Evidence and provenance</h2><p>@@PROVENANCE@@</p>
<p class="muted">Rules were selected on development runs and frozen before held-out traffic collection.
Each completed run is one fixed-duration client–destination window. The first qualifying prefix creates at most one alert.</p>
<p class="muted">Configured minimum for timing-rule prefixes: <strong>@@MIN_EVENTS@@ completed connections</strong>.
Refinement policies, when present, carry their own gates and persistence settings in the frozen model.
These can affect TPR, FPR, coverage, and delay. Client novelty does not use this gate.</p>
<p><strong>Observation backend:</strong> <code>@@OBSERVER@@</code> ·
<strong>Failed runs excluded:</strong> @@FAILED@@</p></section>
<section><h2>Held-out results</h2><div class="scroll"><table><thead><tr>
<th>Detector</th><th>Transport</th><th>Scored / total</th><th>TP / FN</th><th>FP / TN</th>
<th>TPR</th><th>FPR</th><th>Precision</th><th>Median detection (s)</th>
</tr></thead><tbody>@@TOTALS@@</tbody></table></div>
<p class="muted">N/A means the feature or denominator is unavailable—not zero. Coverage must be considered alongside detection rates.</p>
@@FIGURES@@</section>
@@PAIRED@@
<section><h2>Uncertainty and alert burden</h2><div class="scroll"><table><thead><tr>
<th>Detector · both transports</th><th>TPR · 95% interval</th><th>FPR · 95% interval</th>
<th>False alerts / benign client-hour</th><th>Precision at assumed 1:50</th>
</tr></thead><tbody>@@UNCERTAINTY@@</tbody></table></div>
<p class="muted">Intervals are approximate Wilson intervals at the run level; shared generator and environment limit independence. The accelerated pilot's client-hour
rates are normalized measurements, not forecasts of production alert volume. A zero observed FPR can still have a wide interval.</p></section>
<section><h2>Base-rate sensitivity</h2><p>Change the assumed ratio below. This calculation holds the measured TPR/FPR
constant and is a hypothetical scenario, not a claim about a real network.</p>
<div class="calculator"><div><label for="detector">Detector</label><select id="detector">@@OPTIONS@@</select></div>
<div><label for="ratio">Benign windows per simulated-channel window</label><input id="ratio" type="number" min="1" max="1000000" value="50"></div>
<div class="result" aria-live="polite"><span>Prevalence-adjusted precision</span><strong id="precision"></strong><span id="counts"></span></div></div>
<p class="muted">Precision = TPR × prevalence / [TPR × prevalence + FPR × (1 − prevalence)].</p></section>
<section><h2>Where the combined rule succeeds or fails</h2><div class="scroll"><table><thead><tr>
<th>Detector</th><th>Workload</th><th>Transport</th><th>Ground-truth class</th><th>Scored / total</th><th>Flagged fraction</th>
</tr></thead><tbody>@@PROFILES@@</tbody></table></div>
<p class="muted">For simulated channels, flagged fraction is recall. For benign workloads, it is a false-positive rate.
The same held-out benign set supports comparison of the two simulated timing conditions.</p></section>
<section><h2>Frozen model</h2><p>Timing and request-size variation are the only numeric predictors.
IP addresses, ports, payload markers, profile names, and absolute timestamps are excluded from the prediction rules.</p>
<details><summary>Show exact model and development run IDs</summary><pre>@@MODEL@@</pre></details>
<p>The client-novelty baseline compares HTTP User-Agent or HTTPS JA3 against values seen in benign development traffic.
An alert means an unseen observable signal relative to that reference population, not an attacker.
Legitimate client-stack changes or incomplete benign training coverage can produce alerts.
All generated clients deliberately use the same library and User-Agent. A shared fingerprint is not evidence of maliciousness.</p></section>
<section><h2>Limits and next checks</h2><ul>@@NOTES@@</ul>
<p>Collect longer runs, include independently sourced benign traffic, and validate the packet-capture/Zeek path before making operational claims.
TLS changes the available evidence; a performance drop is not a predetermined outcome.</p></section>
<footer>Experiment: BeaconLab @@VERSION@@ · report generator: @@REPORT_VERSION@@ · generated from recorded experiments, not invented metric values.
Data files: <a href="metrics.json">metrics.json</a> · <a href="metrics.csv">metrics.csv</a> · <a href="predictions.csv">predictions.csv</a>.
Sources and method are documented in the project README and research protocol.</footer>
</main><script>
const rows=@@JSON@@;
function update(){
 const row=rows[Number(document.getElementById("detector").value)];
 const ratio=Number(document.getElementById("ratio").value);
 const out=document.getElementById("precision"), counts=document.getElementById("counts");
 if(!row || !Number.isFinite(ratio) || ratio<1 || row.tpr===null || row.fpr===null){
  out.textContent="N/A";counts.textContent="Insufficient measurements or invalid ratio.";return;
 }
 const p=1/(1+ratio), tp=10000*p*row.tpr, fp=10000*(1-p)*row.fpr;
 out.textContent=(tp+fp)>0?(100*tp/(tp+fp)).toFixed(1)+"%":"N/A";
 counts.textContent=(tp+fp)>0?tp.toFixed(1)+" true and "+fp.toFixed(1)+" false alerts per 10,000 windows (expected).":"The measured rule produced no alerts; precision is undefined.";
}
document.getElementById("detector").addEventListener("change",update);
document.getElementById("ratio").addEventListener("input",update);update();
</script></body></html>
"""
    replacements = {
        "DEV": str(summary["n_development"]), "TEST": str(summary["n_test"]),
        "CONNECTIONS": str(connections), "PROVENANCE": html.escape(provenance),
        "OBSERVER": html.escape(primary), "FAILED": str(summary["failed_runs_excluded"]),
        "TOTALS": "".join(totals), "FIGURES": figure_html, "UNCERTAINTY": "".join(uncertainty),
        "PROFILES": "".join(profile_rows), "MODEL": html.escape(json.dumps(model, indent=2)),
        "NOTES": notes, "OPTIONS": options, "JSON": json_data, "VERSION": manifest["version"],
        "MIN_EVENTS": html.escape(str(manifest["config"]["min_events"])), "REPORT_VERSION": __version__,
        "DETECTORS": str(len(model["rules"])), "FINDINGS": finding_html, "PAIRED": paired_html,
    }
    for key, value in replacements.items():
        page = page.replace("@@" + key + "@@", value)
    (output / "report.html").write_text(page, encoding="utf-8")
    markdown = [
        "# BeaconLab experiment results", "",
        "**Synthetic lab traffic; pilot evidence, not production validation.**", "",
        provenance, "",
        f"Development runs: {summary['n_development']}. Held-out runs: {summary['n_test']}.",
        f"Observer: {primary}. Failed runs excluded: {summary['failed_runs_excluded']}.", "",
        "| Detector | Transport | Scored/total | TP/FN | FP/TN | TPR | FPR | Precision |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary["groups"]:
        markdown.append(
            f"| {DISPLAY[row['detector']]} | {row['transport']} | {row['n_scored']}/{row['n_total']} | "
            f"{row['tp']}/{row['fn']} | {row['fp']}/{row['tn']} | {pct(row['tpr'])} | "
            f"{pct(row['fpr'])} | {pct(row['precision'])} |")
    markdown += ["", "## Conclusions", ""] + ["- " + note for note in findings]
    markdown += ["", "## Limitations", ""] + ["- " + note for note in summary["notes"]]
    markdown += ["", "The HTML report includes confidence intervals, profile results, and an interactive base-rate calculation.", ""]
    (output / "RESULTS.md").write_text("\n".join(markdown), encoding="utf-8")
