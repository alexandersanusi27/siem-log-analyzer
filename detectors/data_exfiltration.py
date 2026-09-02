"""
Data Exfiltration Detector — MITRE ATT&CK T1048 (Exfiltration Over Alternative Protocol)

Analyses Zeek conn.log network flows for abnormally large outbound data transfers
to external (non-RFC-1918) destinations.

Two triggers:
  1. Single session:  orig_bytes > SINGLE_SESSION_MB
  2. Cumulative:      total orig_bytes to same (src, dst) pair > TOTAL_EXFIL_MB

Outbound bytes = orig_bytes (bytes sent FROM the internal host).
"""
from collections import defaultdict
from typing import List

from models import Alert, LogEvent
from utils.geoip import is_private_ip, lookup_ip

SINGLE_SESSION_MB = 50    # flag a single flow this large
TOTAL_EXFIL_MB    = 150   # flag cumulative transfers to same destination


def detect(events: List[LogEvent]) -> List[Alert]:
    # (src_ip, dst_ip) -> list of (timestamp, bytes_sent, event)
    flows: dict = defaultdict(list)

    for e in events:
        if e.event_type != "NETWORK_CONN":
            continue
        if not e.dest_ip or is_private_ip(e.dest_ip):
            continue  # only care about external destinations
        if not e.source_ip:
            continue

        raw = e.extra.get("orig_bytes", "-")
        try:
            sent = int(raw)
        except (ValueError, TypeError):
            continue

        if sent <= 0:
            continue

        flows[(e.source_ip, e.dest_ip)].append((e.timestamp, sent, e))

    alerts: List[Alert] = []
    seen_pairs: set = set()

    for (src, dst), flow_list in flows.items():
        total_bytes  = sum(b for _, b, _ in flow_list)
        max_single   = max(b for _, b, _ in flow_list)
        total_mb     = total_bytes  / (1024 * 1024)
        max_single_mb = max_single / (1024 * 1024)

        if total_mb < TOTAL_EXFIL_MB and max_single_mb < SINGLE_SESSION_MB:
            continue

        pair = (src, dst)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)

        # Geo-enrich destination
        geo = lookup_ip(dst)
        dst_label = f"{geo['city']}, {geo['country']}" if geo else dst

        severity = (
            "CRITICAL" if total_mb >= 500
            else "HIGH"  if total_mb >= 200
            else "MEDIUM"
        )
        score = min(100, int(55 + min(total_mb / 10, 45)))

        alerts.append(Alert(
            severity=severity,
            alert_type="DATA_EXFILTRATION",
            title=f"Data Exfiltration: {src} -> {dst}",
            description=(
                f"Host {src} transferred {total_mb:.1f} MB of data to "
                f"external destination {dst} ({dst_label}) "
                f"across {len(flow_list)} flow(s). "
                f"Largest single session: {max_single_mb:.1f} MB."
            ),
            score=score,
            first_seen=min(t for t, _, _ in flow_list),
            last_seen=max(t for t, _, _ in flow_list),
            involved_ips=[src, dst],
            event_count=len(flow_list),
            details={
                "source_host":         src,
                "destination_ip":      dst,
                "destination_location": dst_label,
                "total_transferred_mb":  round(total_mb, 2),
                "largest_session_mb":    round(max_single_mb, 2),
                "session_count":         len(flow_list),
                "single_session_threshold_mb": SINGLE_SESSION_MB,
                "total_threshold_mb":    TOTAL_EXFIL_MB,
            },
            mitre_technique="T1048 - Exfiltration Over Alternative Protocol",
        ))

    return alerts
