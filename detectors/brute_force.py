"""
Brute Force Detector — MITRE ATT&CK T1110

Looks for high volumes of AUTH_FAILURE events from a single source IP
within a rolling time window. Escalates severity if a successful login
follows the failure burst (indicates successful credential compromise).
"""
from collections import defaultdict
from datetime import timedelta
from typing import List

from models import Alert, LogEvent

WINDOW_MINUTES = 10

# (min_count, severity, base_score, label)
THRESHOLDS = [
    (50, "CRITICAL", 90, "Massive brute-force attack"),
    (20, "HIGH",     75, "Active brute-force attack"),
    (5,  "MEDIUM",   50, "Possible brute-force attempt"),
]


def detect(events: List[LogEvent]) -> List[Alert]:
    # Group failures by source IP
    failures: dict = defaultdict(list)
    for e in events:
        if e.event_type == "AUTH_FAILURE" and e.source_ip:
            failures[e.source_ip].append(e)

    alerts: List[Alert] = []

    for ip, evts in failures.items():
        evts.sort(key=lambda e: e.timestamp)

        # Sliding window — find the maximum burst count
        max_count = 0
        best_window: List[LogEvent] = []
        win_start = 0

        for i in range(len(evts)):
            while (evts[i].timestamp - evts[win_start].timestamp) > timedelta(minutes=WINDOW_MINUTES):
                win_start += 1
            window_size = i - win_start + 1
            if window_size > max_count:
                max_count = window_size
                best_window = evts[win_start : i + 1]

        if max_count < 5:
            continue

        severity, score, label = "LOW", 30, "Suspicious login activity"
        for threshold, sev, sc, lbl in THRESHOLDS:
            if max_count >= threshold:
                severity, score, label = sev, sc, lbl
                break

        # Check for success immediately after the burst
        burst_end = best_window[-1].timestamp
        success_after = any(
            e.event_type == "AUTH_SUCCESS"
            and e.source_ip == ip
            and e.timestamp >= burst_end
            for e in events
        )
        if success_after:
            score = min(100, score + 15)
            if severity == "HIGH":
                severity = "CRITICAL"

        usernames = sorted(set(e.username for e in best_window if e.username))
        hosts     = sorted(set(e.hostname for e in best_window if e.hostname))

        alerts.append(Alert(
            severity=severity,
            alert_type="BRUTE_FORCE",
            title=f"Brute Force: {ip}",
            description=(
                f"{label} from {ip}. {max_count} failed attempts within "
                f"{WINDOW_MINUTES}-minute window targeting: "
                f"{', '.join(usernames) or 'unknown'}."
                + (
                    " ACCOUNT COMPROMISED — successful login followed the burst."
                    if success_after else ""
                )
            ),
            score=score,
            first_seen=best_window[0].timestamp,
            last_seen=best_window[-1].timestamp,
            involved_ips=[ip],
            involved_users=usernames,
            event_count=max_count,
            details={
                "failed_attempts": max_count,
                "targeted_users": usernames,
                "affected_hosts": hosts,
                "successful_compromise": success_after,
                "detection_window_minutes": WINDOW_MINUTES,
            },
            mitre_technique="T1110 - Brute Force",
        ))

    return alerts
