"""
Impossible Travel Detector — MITRE ATT&CK T1078 (Valid Accounts)

Flags cases where the same user logs in from two geographically distant
locations within a timeframe too short for physical travel to be possible.

The physics check: if the implied travel speed exceeds MAX_SPEED_KMH
(fastest commercial aircraft), the login pair is flagged.
"""
from collections import defaultdict
from typing import List

from models import Alert, LogEvent
from utils.geoip import haversine_km, is_private_ip, lookup_ip

MAX_SPEED_KMH = 900   # approx. max commercial aircraft speed
MIN_DISTANCE_KM = 200  # ignore logins within the same metro area


def detect(events: List[LogEvent]) -> List[Alert]:
    # Build per-user timeline of geolocated successful logins
    user_logins: dict = defaultdict(list)

    for e in events:
        if (
            e.event_type == "AUTH_SUCCESS"
            and e.source_ip
            and not is_private_ip(e.source_ip)
            and e.username
        ):
            geo = lookup_ip(e.source_ip)
            if geo:
                user_logins[e.username].append(
                    (e.timestamp, e.source_ip, geo, e)
                )

    alerts: List[Alert] = []

    for username, logins in user_logins.items():
        logins.sort(key=lambda x: x[0])

        for i in range(len(logins) - 1):
            t1, ip1, geo1, _ = logins[i]
            t2, ip2, geo2, _ = logins[i + 1]

            if ip1 == ip2:
                continue

            dist_km = haversine_km(geo1["lat"], geo1["lon"], geo2["lat"], geo2["lon"])
            if dist_km < MIN_DISTANCE_KM:
                continue

            time_hours = (t2 - t1).total_seconds() / 3600
            if time_hours <= 0:
                continue

            speed_kmh = dist_km / time_hours

            if speed_kmh <= MAX_SPEED_KMH:
                continue

            severity = "CRITICAL" if time_hours < 0.5 else "HIGH"
            score = min(100, int(70 + min((speed_kmh - MAX_SPEED_KMH) / 200, 30)))

            alerts.append(Alert(
                severity=severity,
                alert_type="IMPOSSIBLE_TRAVEL",
                title=f"Impossible Travel: {username}",
                description=(
                    f"User '{username}' logged in from "
                    f"{geo1['city']}, {geo1['country']} ({ip1}) "
                    f"then {geo2['city']}, {geo2['country']} ({ip2}) "
                    f"{time_hours * 60:.0f} minutes later — "
                    f"{dist_km:.0f} km apart at {speed_kmh:.0f} km/h. "
                    f"Physically impossible. Likely account compromise or credential sharing."
                ),
                score=score,
                first_seen=t1,
                last_seen=t2,
                involved_ips=[ip1, ip2],
                involved_users=[username],
                event_count=2,
                details={
                    "from_location": f"{geo1['city']}, {geo1['country']}",
                    "to_location":   f"{geo2['city']}, {geo2['country']}",
                    "from_ip": ip1,
                    "to_ip":   ip2,
                    "distance_km":        round(dist_km),
                    "time_between_mins":  round(time_hours * 60, 1),
                    "implied_speed_kmh":  round(speed_kmh),
                    "max_possible_kmh":   MAX_SPEED_KMH,
                },
                mitre_technique="T1078 - Valid Accounts",
            ))

    return alerts
