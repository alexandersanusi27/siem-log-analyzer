"""
Lateral Movement Detector — MITRE ATT&CK T1021, T1046

Two detection strategies:

1. Auth-log: a single source IP authenticates successfully to N or more
   distinct hosts within a rolling time window.

2. Zeek/network: a single internal IP initiates connections to many hosts
   on administrative ports (SSH, RDP, SMB, WinRM, Telnet) — indicates
   internal scanning or tool-based lateral movement.
"""
from collections import defaultdict
from datetime import timedelta
from typing import List

from models import Alert, LogEvent

AUTH_HOST_THRESHOLD = 3   # distinct hosts in window to trigger
AUTH_WINDOW_HOURS   = 2

ADMIN_PORTS = {22, 23, 135, 445, 3389, 5985, 5986}
NET_HOST_THRESHOLD = 5    # distinct targets on admin ports to trigger


def detect(events: List[LogEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    alerts.extend(_detect_auth_lateral(events))
    alerts.extend(_detect_network_lateral(events))
    return _deduplicate(alerts)


# ---------------------------------------------------------------------------
# Strategy 1 — authentication-based lateral movement
# ---------------------------------------------------------------------------

def _detect_auth_lateral(events: List[LogEvent]) -> List[Alert]:
    # source_ip -> [(timestamp, hostname, username)]
    successes: dict = defaultdict(list)
    for e in events:
        if e.event_type == "AUTH_SUCCESS" and e.source_ip and e.hostname:
            successes[e.source_ip].append(
                (e.timestamp, e.hostname, e.username or "unknown")
            )

    alerts: List[Alert] = []
    for ip, logins in successes.items():
        logins.sort(key=lambda x: x[0])

        for i, (ts, _, _) in enumerate(logins):
            window = [
                (t, h, u) for (t, h, u) in logins
                if ts <= t <= ts + timedelta(hours=AUTH_WINDOW_HOURS)
            ]
            unique_hosts = set(h for _, h, _ in window)

            if len(unique_hosts) >= AUTH_HOST_THRESHOLD:
                users = sorted(set(u for _, _, u in window))
                host_count = len(unique_hosts)
                severity = (
                    "CRITICAL" if host_count >= 6
                    else "HIGH" if host_count >= 4
                    else "MEDIUM"
                )
                score = min(100, 50 + (host_count - AUTH_HOST_THRESHOLD) * 10)

                alerts.append(Alert(
                    severity=severity,
                    alert_type="LATERAL_MOVEMENT",
                    title=f"Lateral Movement (Auth): {ip}",
                    description=(
                        f"Source IP {ip} authenticated to {host_count} distinct hosts "
                        f"within {AUTH_WINDOW_HOURS}h: "
                        f"{', '.join(sorted(unique_hosts))}."
                    ),
                    score=score,
                    first_seen=window[0][0],
                    last_seen=window[-1][0],
                    involved_ips=[ip],
                    involved_users=users,
                    event_count=len(window),
                    details={
                        "hosts_accessed": sorted(unique_hosts),
                        "host_count": host_count,
                        "time_window_hours": AUTH_WINDOW_HOURS,
                    },
                    mitre_technique="T1021 - Remote Services",
                ))
                break  # one alert per source IP

    return alerts


# ---------------------------------------------------------------------------
# Strategy 2 — network-based lateral movement (Zeek)
# ---------------------------------------------------------------------------

def _detect_network_lateral(events: List[LogEvent]) -> List[Alert]:
    # source_ip -> port -> set of dest IPs
    conns: dict = defaultdict(lambda: defaultdict(set))
    for e in events:
        if (
            e.event_type == "NETWORK_CONN"
            and e.source_ip
            and e.dest_ip
            and e.dest_port in ADMIN_PORTS
        ):
            conns[e.source_ip][e.dest_port].add(e.dest_ip)

    alerts: List[Alert] = []
    for ip, port_map in conns.items():
        all_targets: set = set()
        for hosts in port_map.values():
            all_targets |= hosts

        if len(all_targets) < NET_HOST_THRESHOLD:
            continue

        relevant = [
            e for e in events
            if e.event_type == "NETWORK_CONN"
            and e.source_ip == ip
            and e.dest_port in ADMIN_PORTS
        ]
        ports_str = ", ".join(str(p) for p in sorted(port_map.keys()))
        target_count = len(all_targets)
        severity = "HIGH" if target_count >= 10 else "MEDIUM"
        score = min(100, 55 + target_count * 3)

        alerts.append(Alert(
            severity=severity,
            alert_type="LATERAL_MOVEMENT",
            title=f"Internal Scanning / Lateral Movement: {ip}",
            description=(
                f"{ip} connected to {target_count} hosts on admin port(s) "
                f"({ports_str}) — possible internal reconnaissance or lateral movement."
            ),
            score=score,
            first_seen=min(e.timestamp for e in relevant),
            last_seen=max(e.timestamp for e in relevant),
            involved_ips=[ip] + sorted(all_targets)[:10],
            event_count=len(relevant),
            details={
                "target_count": target_count,
                "target_hosts": sorted(all_targets),
                "ports_targeted": sorted(port_map.keys()),
                "connection_count": len(relevant),
            },
            mitre_technique="T1046 - Network Service Discovery / T1021 - Remote Services",
        ))

    return alerts


def _deduplicate(alerts: List[Alert]) -> List[Alert]:
    seen: set = set()
    unique: List[Alert] = []
    for a in alerts:
        key = (a.alert_type, a.involved_ips[0] if a.involved_ips else "")
        if key not in seen:
            seen.add(key)
            unique.append(a)
    return unique
