"""
Off-Hours Login Detector — MITRE ATT&CK T1078 (Valid Accounts)

Flags successful authentications that occur outside normal business hours
or on weekends. Combined with an external source IP, severity escalates.

Business hours default: 08:00-18:00, Monday-Friday.
Logins at 00:00-05:59 on any day are treated as highest suspicion.
"""
from typing import List

from models import Alert, LogEvent
from utils.geoip import is_private_ip

BUSINESS_START = 8    # 08:00
BUSINESS_END   = 18   # 18:00
DEAD_ZONE_END  = 5    # 00:00-05:59 = highest suspicion

WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
WEEKEND  = {5, 6}  # Saturday, Sunday


def detect(events: List[LogEvent]) -> List[Alert]:
    alerts: List[Alert] = []

    for e in events:
        if e.event_type != "AUTH_SUCCESS" or not e.username:
            continue

        hour    = e.timestamp.hour
        weekday = e.timestamp.weekday()

        is_weekend     = weekday in WEEKEND
        is_after_hours = hour < BUSINESS_START or hour >= BUSINESS_END
        is_dead_zone   = hour < DEAD_ZONE_END   # 00:00-05:59

        if not (is_weekend or is_after_hours):
            continue

        # Base severity / score
        if is_dead_zone:
            severity, score, label = "HIGH", 70, "Dead-zone login (00:00-05:59)"
        elif is_weekend and is_after_hours:
            severity, score, label = "HIGH", 65, "Weekend after-hours login"
        elif is_weekend:
            severity, score, label = "MEDIUM", 50, "Weekend login"
        else:
            severity, score, label = "LOW", 35, "After-hours login"

        # External source IP escalates
        external = bool(e.source_ip and not is_private_ip(e.source_ip))
        if external:
            score = min(100, score + 20)
            if severity == "MEDIUM":
                severity = "HIGH"
            elif severity == "LOW":
                severity = "MEDIUM"

        alerts.append(Alert(
            severity=severity,
            alert_type="OFF_HOURS_LOGIN",
            title=f"Off-Hours Login: {e.username}",
            description=(
                f"{label} — user '{e.username}' authenticated from "
                f"{e.source_ip or 'unknown'} at "
                f"{e.timestamp.strftime('%H:%M:%S')} "
                f"({WEEKDAYS[weekday]})."
                + (" Source IP is external." if external else "")
            ),
            score=score,
            first_seen=e.timestamp,
            last_seen=e.timestamp,
            involved_ips=[e.source_ip] if e.source_ip else [],
            involved_users=[e.username],
            event_count=1,
            details={
                "login_time":      e.timestamp.strftime("%H:%M:%S"),
                "day_of_week":     WEEKDAYS[weekday],
                "is_weekend":      is_weekend,
                "is_dead_zone":    is_dead_zone,
                "external_source": external,
                "hostname":        e.hostname,
                "business_hours":  f"{BUSINESS_START:02d}:00-{BUSINESS_END:02d}:00 Mon-Fri",
            },
            mitre_technique="T1078 - Valid Accounts",
        ))

    return alerts
