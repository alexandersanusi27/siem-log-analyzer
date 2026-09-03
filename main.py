#!/usr/bin/env python3
"""
SIEM Log Analyzer
-----------------
Ingest SSH auth logs, Windows Event Logs (JSON), and Zeek conn logs,
then detect: brute force, lateral movement, privilege escalation,
and impossible travel logins.

Usage:
  python main.py --demo
  python main.py --ssh sample_logs/auth.log
  python main.py --ssh sample_logs/auth.log --windows sample_logs/windows_events.json
  python main.py --ssh sample_logs/auth.log --min-severity HIGH --output json
"""
import argparse
import json
import os
import sys
from dataclasses import asdict
from typing import List

from models import Alert, SEVERITY_ORDER


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="siem-analyzer",
        description="Detect security threats in aggregated log files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--ssh",     nargs="+", metavar="FILE", help="SSH auth.log file(s)")
    p.add_argument("--windows", nargs="+", metavar="FILE", help="Windows Event Log JSON file(s)")
    p.add_argument("--zeek",    nargs="+", metavar="FILE", help="Zeek conn.log file(s)")
    p.add_argument("--nginx",   nargs="+", metavar="FILE", help="nginx/Apache access log file(s)")
    p.add_argument(
        "--detectors", nargs="+",
        choices=["brute_force", "lateral_movement", "privilege_escalation", "impossible_travel",
                 "off_hours", "credential_stuffing", "data_exfiltration", "web_attacks"],
        help="Run only specific detectors (default: all)",
    )
    p.add_argument(
        "--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW", metavar="LEVEL",
        help="Minimum severity level to display (default: LOW)",
    )
    p.add_argument(
        "--output", choices=["terminal", "json", "csv", "html"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    p.add_argument(
        "--demo", action="store_true",
        help="Run analysis on the bundled sample log files",
    )
    p.add_argument(
        "--watch", action="store_true",
        help="Tail log file(s) and alert on new events in real time (polls every 5s)",
    )
    p.add_argument(
        "--watch-interval", type=int, default=5, metavar="SECONDS",
        help="Polling interval for --watch mode (default: 5)",
    )
    return p


# ---------------------------------------------------------------------------
# Log loading
# ---------------------------------------------------------------------------

def load_events(args):
    events = []
    stats  = {}

    if args.ssh:
        from parsers.ssh import parse_ssh_log
        for path in args.ssh:
            evts = parse_ssh_log(path)
            events.extend(evts)
            stats["ssh"] = stats.get("ssh", 0) + len(evts)
            print(f"  [ssh]     {len(evts):>5} events  <- {path}")

    if args.windows:
        from parsers.windows import parse_windows_log
        for path in args.windows:
            evts = parse_windows_log(path)
            events.extend(evts)
            stats["windows"] = stats.get("windows", 0) + len(evts)
            print(f"  [windows] {len(evts):>5} events  <- {path}")

    if args.zeek:
        from parsers.zeek import parse_zeek_conn_log
        for path in args.zeek:
            evts = parse_zeek_conn_log(path)
            events.extend(evts)
            stats["zeek"] = stats.get("zeek", 0) + len(evts)
            print(f"  [zeek]    {len(evts):>5} events  <- {path}")

    if getattr(args, "nginx", None):
        from parsers.nginx import parse_nginx_log
        for path in args.nginx:
            evts = parse_nginx_log(path)
            events.extend(evts)
            stats["nginx"] = stats.get("nginx", 0) + len(evts)
            print(f"  [nginx]   {len(evts):>5} events  <- {path}")

    return events, stats


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

_DETECTOR_MODULES = {
    "brute_force":          "detectors.brute_force",
    "lateral_movement":     "detectors.lateral_movement",
    "privilege_escalation": "detectors.privilege_escalation",
    "impossible_travel":    "detectors.impossible_travel",
    "off_hours":            "detectors.off_hours",
    "credential_stuffing":  "detectors.credential_stuffing",
    "data_exfiltration":    "detectors.data_exfiltration",
    "web_attacks":          "detectors.web_attacks",
}


def run_detectors(events, detector_names: List[str]) -> List[Alert]:
    all_alerts: List[Alert] = []

    for name in detector_names:
        mod_path = _DETECTOR_MODULES[name]
        mod = __import__(mod_path, fromlist=["detect"])
        found = mod.detect(events)
        label = name.replace("_", " ").title()
        print(f"  [{label}] {len(found)} alert(s)")
        all_alerts.extend(found)

    # Sort: highest severity and score first
    all_alerts.sort(
        key=lambda a: (SEVERITY_ORDER.get(a.severity, 0), a.score),
        reverse=True,
    )
    return all_alerts


# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------

def output_terminal(alerts: List[Alert], stats: dict) -> None:
    from dashboard.terminal import render_dashboard
    render_dashboard(alerts, stats)


def output_json(alerts: List[Alert]) -> None:
    records = []
    for a in alerts:
        d = asdict(a)
        d["first_seen"] = a.first_seen.isoformat()
        d["last_seen"]  = a.last_seen.isoformat()
        records.append(d)
    print(json.dumps(records, indent=2, default=str))


def output_csv(alerts: List[Alert]) -> None:
    import csv
    writer = csv.writer(sys.stdout)
    writer.writerow([
        "Rank", "Severity", "Type", "Score", "Title",
        "IPs", "Users", "Events", "First Seen", "Last Seen", "MITRE",
    ])
    for i, a in enumerate(alerts, 1):
        writer.writerow([
            i, a.severity, a.alert_type, a.score, a.title,
            "|".join(a.involved_ips),
            "|".join(a.involved_users),
            a.event_count,
            a.first_seen.isoformat(),
            a.last_seen.isoformat(),
            a.mitre_technique or "",
        ])


# ---------------------------------------------------------------------------
# Watch mode — tail log files and alert on new events in real time
# ---------------------------------------------------------------------------

def _watch_mode(args, detectors: List[str]) -> None:
    import time

    # Collect (parser_fn, filepath) pairs and track file positions
    sources = []
    if args.ssh:
        from parsers.ssh import parse_ssh_log
        for p in args.ssh:
            sources.append(("ssh", p, parse_ssh_log))
    if getattr(args, "nginx", None):
        from parsers.nginx import parse_nginx_log
        for p in args.nginx:
            sources.append(("nginx", p, parse_nginx_log))

    if not sources:
        print("[!] --watch currently supports --ssh and --nginx log files.")
        return

    # Record initial file sizes so we only process new lines
    file_positions = {}
    for _, path, _ in sources:
        try:
            file_positions[path] = os.path.getsize(path)
        except OSError:
            file_positions[path] = 0

    min_sev = SEVERITY_ORDER.get(args.min_severity, 0)
    interval = args.watch_interval

    print(f"\n[watch] Monitoring {len(sources)} file(s). Polling every {interval}s. Ctrl+C to stop.\n")

    seen_alert_keys: set = set()

    while True:
        time.sleep(interval)
        new_events = []

        for fmt, path, parse_fn in sources:
            try:
                current_size = os.path.getsize(path)
            except OSError:
                continue

            prev_pos = file_positions.get(path, 0)
            if current_size <= prev_pos:
                continue

            # Read only the new portion of the file
            with open(path, "r", errors="replace") as fh:
                fh.seek(prev_pos)
                new_lines = fh.read()
            file_positions[path] = current_size

            # Write new lines to a temp file and parse it
            import tempfile
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=f".{fmt}.log", delete=False, errors="replace"
            ) as tmp:
                tmp.write(new_lines)
                tmp_path = tmp.name

            try:
                evts = parse_fn(tmp_path)
                new_events.extend(evts)
            finally:
                os.unlink(tmp_path)

        if not new_events:
            continue

        alerts = run_detectors(new_events, detectors)
        alerts = [a for a in alerts if SEVERITY_ORDER.get(a.severity, 0) >= min_sev]

        for alert in alerts:
            # Deduplicate against previously seen alerts
            key = (alert.alert_type, tuple(alert.involved_ips), tuple(alert.involved_users))
            if key in seen_alert_keys:
                continue
            seen_alert_keys.add(key)

            from dashboard.terminal import _render_detail_panel
            _render_detail_panel(len(seen_alert_keys), alert)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if args.demo:
        args.ssh     = ["sample_logs/auth.log"]
        args.windows = ["sample_logs/windows_events.json"]
        args.zeek    = ["sample_logs/zeek_conn.log"]
        args.nginx   = ["sample_logs/nginx_access.log"]

    if not (args.ssh or args.windows or args.zeek or getattr(args, "nginx", None)):
        parser.print_help()
        print("\n  Tip: run with --demo to try the bundled sample logs.")
        sys.exit(1)

    detectors = args.detectors or list(_DETECTOR_MODULES.keys())

    if args.watch:
        _watch_mode(args, detectors)
        return

    print("\nLoading logs...")
    events, stats = load_events(args)
    print(f"  Total events loaded: {len(events)}\n")

    print("Running detectors...")
    alerts = run_detectors(events, detectors)

    print("Running threat intel enrichment...")
    from utils.threat_intel import enrich_alerts
    enrich_alerts(alerts)

    # Re-sort after enrichment (scores and severities may have changed)
    alerts.sort(
        key=lambda a: (SEVERITY_ORDER.get(a.severity, 0), a.score),
        reverse=True,
    )

    # Filter by minimum severity
    min_sev = SEVERITY_ORDER.get(args.min_severity, 0)
    alerts  = [a for a in alerts if SEVERITY_ORDER.get(a.severity, 0) >= min_sev]
    print(f"  Alerts after severity filter (>= {args.min_severity}): {len(alerts)}\n")

    if args.output == "terminal":
        output_terminal(alerts, stats)
    elif args.output == "json":
        output_json(alerts)
    elif args.output == "csv":
        output_csv(alerts)
    elif args.output == "html":
        from dashboard.html_report import generate_html_report
        from datetime import datetime
        filename = f"siem_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        generate_html_report(alerts, stats, filename)


if __name__ == "__main__":
    main()
