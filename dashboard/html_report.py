"""
HTML report generator.

Produces a single self-contained HTML file with:
  - Summary statistics
  - Colour-coded ranked alert table
  - Expandable detail section per alert
"""
import html
from datetime import datetime
from typing import Dict, List

from models import Alert

_SEVERITY_COLOUR = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#27ae60",
}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; }
.container { max-width: 1200px; margin: 0 auto; padding: 24px; }
h1 { font-size: 1.6rem; color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 12px; margin-bottom: 20px; }
h2 { font-size: 1.1rem; color: #8b949e; margin: 24px 0 12px; }
.meta { color: #8b949e; font-size: 0.85rem; margin-bottom: 20px; }
.summary { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 28px; }
.stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 24px; min-width: 140px; }
.stat-card .value { font-size: 2rem; font-weight: bold; }
.stat-card .label { font-size: 0.8rem; color: #8b949e; margin-top: 4px; }
.CRITICAL { color: #c0392b; }
.HIGH     { color: #e67e22; }
.MEDIUM   { color: #f1c40f; }
.LOW      { color: #27ae60; }
table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; margin-bottom: 32px; }
thead tr { background: #1f2937; }
th { padding: 10px 14px; text-align: left; font-size: 0.8rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }
td { padding: 10px 14px; font-size: 0.875rem; border-top: 1px solid #21262d; vertical-align: top; }
tr:hover td { background: #1c2128; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; color: #fff; }
.score-bar { height: 6px; border-radius: 3px; background: #21262d; margin-top: 4px; }
.score-fill { height: 100%; border-radius: 3px; }
.detail-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
.detail-header { padding: 14px 18px; border-bottom: 1px solid #30363d; display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
.detail-header:hover { background: #1c2128; }
.detail-body { padding: 16px 18px; display: none; }
.detail-body.open { display: block; }
.kv { display: flex; gap: 12px; margin-bottom: 8px; font-size: 0.85rem; }
.kv .k { color: #8b949e; min-width: 180px; }
.kv .v { color: #c9d1d9; }
.mitre { margin-top: 12px; font-size: 0.8rem; color: #8b949e; font-style: italic; }
footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #30363d; font-size: 0.8rem; color: #8b949e; text-align: center; }
"""

_JS = """
document.querySelectorAll('.detail-header').forEach(h => {
    h.addEventListener('click', () => {
        h.nextElementSibling.classList.toggle('open');
    });
});
"""


def generate_html_report(alerts: List[Alert], log_stats: Dict[str, int], output_path: str) -> None:
    now = datetime.now()
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        counts[a.severity] = counts.get(a.severity, 0) + 1

    body_parts = [
        f"<!DOCTYPE html><html lang='en'><head>",
        f"<meta charset='UTF-8'>",
        f"<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
        f"<title>SIEM Alert Report — {now.strftime('%Y-%m-%d %H:%M')}</title>",
        f"<style>{_CSS}</style>",
        f"</head><body><div class='container'>",
        f"<h1>SIEM Log Analyzer — Alert Report</h1>",
        f"<p class='meta'>Generated: {now.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; "
        f"Events analysed: {sum(log_stats.values()):,} "
        f"({', '.join(f'{k.upper()}: {v}' for k, v in log_stats.items())})</p>",
    ]

    # Summary cards
    ti_ip_count = len({
        hit["ip"]
        for a in alerts
        for hit in a.details.get("threat_intel", [])
    })
    body_parts.append("<div class='summary'>")
    body_parts.append(_stat_card(str(len(alerts)), "Total Alerts", "#58a6ff"))
    for sev, colour in _SEVERITY_COLOUR.items():
        body_parts.append(_stat_card(str(counts[sev]), sev, colour))
    if ti_ip_count:
        body_parts.append(_stat_card(str(ti_ip_count), "Known-Bad IPs", "#c0392b"))
    body_parts.append("</div>")

    # Alert table
    body_parts.append("<h2>Ranked Alerts</h2>")
    body_parts.append("<table><thead><tr>")
    for col in ["#", "Severity", "Type", "Score", "Source IPs", "Users", "Events", "Title"]:
        body_parts.append(f"<th>{col}</th>")
    body_parts.append("</tr></thead><tbody>")

    for i, a in enumerate(alerts, 1):
        col = _SEVERITY_COLOUR.get(a.severity, "#888")
        ips   = ", ".join(a.involved_ips[:2]) + (f" (+{len(a.involved_ips)-2})" if len(a.involved_ips) > 2 else "")
        users = ", ".join(a.involved_users[:2]) + (f" (+{len(a.involved_users)-2})" if len(a.involved_users) > 2 else "")
        bar_colour = col
        body_parts.append(
            f"<tr>"
            f"<td>{i}</td>"
            f"<td><span class='badge' style='background:{col}'>{html.escape(a.severity)}</span></td>"
            f"<td>{html.escape(a.alert_type.replace('_', ' ').title())}</td>"
            f"<td>{a.score}"
            f"<div class='score-bar'><div class='score-fill' style='width:{a.score}%;background:{bar_colour}'></div></div></td>"
            f"<td>{html.escape(ips or '-')}</td>"
            f"<td>{html.escape(users or '-')}</td>"
            f"<td>{a.event_count}</td>"
            f"<td>{html.escape(a.title)}</td>"
            f"</tr>"
        )
    body_parts.append("</tbody></table>")

    # Detail panels
    body_parts.append("<h2>Alert Details</h2>")
    for i, a in enumerate(alerts, 1):
        col = _SEVERITY_COLOUR.get(a.severity, "#888")
        body_parts.append(f"<div class='detail-card'>")
        body_parts.append(
            f"<div class='detail-header'>"
            f"<span style='color:{col};font-weight:bold'>[{i}] {html.escape(a.title)}</span>"
            f"<span style='color:#8b949e;font-size:0.8rem'>Score: {a.score}/100 &nbsp; "
            f"<span class='badge' style='background:{col}'>{html.escape(a.severity)}</span></span>"
            f"</div>"
        )
        body_parts.append("<div class='detail-body'>")
        body_parts.append(f"<p style='margin-bottom:14px'>{html.escape(a.description)}</p>")

        for k, v in a.details.items():
            if k == "threat_intel":
                body_parts.append(
                    "<div style='margin:12px 0 8px;padding:10px 14px;"
                    "background:#2d1515;border:1px solid #c0392b;border-radius:6px'>"
                    "<div style='color:#c0392b;font-weight:bold;margin-bottom:8px'>"
                    "THREAT INTEL MATCHES</div>"
                )
                for hit in v:
                    cats = html.escape(hit["categories"])
                    body_parts.append(
                        f"<div style='margin-bottom:6px;font-size:0.85rem'>"
                        f"<span style='color:#e74c3c;font-weight:bold'>{html.escape(hit['ip'])}</span>"
                        f" &nbsp; Confidence: <b>{hit['confidence']}%</b>"
                        f" &nbsp; Categories: {cats}"
                        f" &nbsp; Reports: {hit['reports']}"
                        f" &nbsp; <span style='color:#8b949e'>({html.escape(hit['source'])})</span>"
                        f"</div>"
                    )
                body_parts.append("</div>")
                continue
            label = k.replace("_", " ").title()
            if isinstance(v, list):
                val = ", ".join(str(x) for x in v[:8]) + (f" … (+{len(v)-8} more)" if len(v) > 8 else "")
            elif isinstance(v, bool):
                val = "Yes" if v else "No"
            else:
                val = str(v)
            body_parts.append(
                f"<div class='kv'><span class='k'>{html.escape(label)}</span>"
                f"<span class='v'>{html.escape(val)}</span></div>"
            )

        body_parts.append(
            f"<div class='kv'><span class='k'>Time Range</span>"
            f"<span class='v'>{a.first_seen.strftime('%H:%M:%S')} to "
            f"{a.last_seen.strftime('%H:%M:%S')} ({a.first_seen.strftime('%Y-%m-%d')})</span></div>"
        )
        if a.mitre_technique:
            body_parts.append(f"<p class='mitre'>MITRE ATT&CK: {html.escape(a.mitre_technique)}</p>")

        body_parts.append("</div></div>")

    body_parts.append(f"<footer>Generated by SIEM Log Analyzer</footer>")
    body_parts.append(f"</div><script>{_JS}</script></body></html>")

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(body_parts))

    print(f"  HTML report saved: {output_path}")


def _stat_card(value: str, label: str, colour: str) -> str:
    return (
        f"<div class='stat-card'>"
        f"<div class='value' style='color:{colour}'>{html.escape(value)}</div>"
        f"<div class='label'>{html.escape(label)}</div>"
        f"</div>"
    )
