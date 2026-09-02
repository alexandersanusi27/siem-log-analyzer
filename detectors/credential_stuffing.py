"""
Credential Stuffing / Password Spray Detector — MITRE ATT&CK T1110.004 / T1110.003

Credential stuffing:  one IP tries many username:password pairs sourced from
                      leaked credential databases — typically 1-2 attempts per
                      username. Designed to fly under brute-force thresholds.

Password spray:       one IP tries a single common password against many
                      different usernames — avg attempts/user ≈ 1, high unique
                      username count.

Key difference from brute force: brute force = many attempts, FEW usernames.
These attacks = few attempts, MANY usernames.
"""
from collections import defaultdict
from datetime import timedelta
from typing import List

from models import Alert, LogEvent

MIN_UNIQUE_USERS   = 8    # minimum distinct usernames to trigger
MAX_ATTEMPTS_PER_USER = 3 # stuffing = low per-user attempt count
WINDOW_MINUTES     = 15


def detect(events: List[LogEvent]) -> List[Alert]:
    # Group AUTH_FAILURE by source IP
    ip_failures: dict = defaultdict(list)
    for e in events:
        if e.event_type == "AUTH_FAILURE" and e.source_ip and e.username:
            ip_failures[e.source_ip].append(e)

    alerts: List[Alert] = []

    for ip, evts in ip_failures.items():
        evts.sort(key=lambda e: e.timestamp)

        # Sliding window
        win_start = 0
        for i in range(len(evts)):
            while (evts[i].timestamp - evts[win_start].timestamp) > timedelta(minutes=WINDOW_MINUTES):
                win_start += 1

            window = evts[win_start : i + 1]

            # Count attempts per username in this window
            user_counts: dict = defaultdict(int)
            for e in window:
                user_counts[e.username] += 1

            unique_users   = len(user_counts)
            avg_per_user   = sum(user_counts.values()) / max(unique_users, 1)
            spray_users    = [u for u, c in user_counts.items() if c <= MAX_ATTEMPTS_PER_USER]

            if unique_users < MIN_UNIQUE_USERS:
                continue
            if avg_per_user > MAX_ATTEMPTS_PER_USER:
                continue  # Looks more like traditional brute force — skip

            # Classify: spray (avg ~1) vs stuffing (avg ~2-3)
            if avg_per_user <= 1.5:
                attack_type = "Password Spray"
                mitre = "T1110.003 - Password Spraying"
                desc_extra = (
                    f"Each username was attempted ~{avg_per_user:.1f} time(s) — "
                    "classic low-and-slow password spray pattern."
                )
            else:
                attack_type = "Credential Stuffing"
                mitre = "T1110.004 - Credential Stuffing"
                desc_extra = (
                    f"Each username was attempted ~{avg_per_user:.1f} time(s) — "
                    "consistent with replayed leaked credential pairs."
                )

            score    = min(100, 55 + unique_users * 2)
            severity = "HIGH" if unique_users >= 15 else "MEDIUM"

            alerts.append(Alert(
                severity=severity,
                alert_type="CREDENTIAL_STUFFING",
                title=f"{attack_type}: {ip}",
                description=(
                    f"{attack_type} detected from {ip}. "
                    f"{unique_users} distinct usernames targeted within "
                    f"{WINDOW_MINUTES} minutes. {desc_extra}"
                ),
                score=score,
                first_seen=window[0].timestamp,
                last_seen=window[-1].timestamp,
                involved_ips=[ip],
                involved_users=sorted(spray_users)[:10],
                event_count=len(window),
                details={
                    "attack_subtype":        attack_type,
                    "unique_usernames":      unique_users,
                    "avg_attempts_per_user": round(avg_per_user, 2),
                    "total_attempts":        len(window),
                    "sample_usernames":      sorted(spray_users)[:10],
                    "detection_window_mins": WINDOW_MINUTES,
                },
                mitre_technique=mitre,
            ))
            break  # one alert per IP

    return alerts
