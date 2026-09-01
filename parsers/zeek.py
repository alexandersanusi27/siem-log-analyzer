"""
Parser for Zeek (formerly Bro) conn.log files.

Zeek logs use tab-separated values with # comment headers.
Fields are declared in the #fields header line.
"""
from datetime import datetime
from typing import List
from models import LogEvent


def parse_zeek_conn_log(filepath: str) -> List[LogEvent]:
    events: List[LogEvent] = []
    fields: List[str] = []

    with open(filepath, "r", errors="replace") as fh:
        for line in fh:
            line = line.rstrip()

            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line:
                continue
            if not fields:
                continue

            parts = line.split("\t")
            record = dict(zip(fields, parts))

            try:
                ts = float(record.get("ts", 0))
                timestamp = datetime.fromtimestamp(ts)
            except (ValueError, OSError):
                timestamp = datetime.now()

            src_ip = record.get("id.orig_h")
            dst_ip = record.get("id.resp_h")

            try:
                dst_port = int(record.get("id.resp_p", 0))
            except ValueError:
                dst_port = 0

            service = record.get("service", "-")
            proto = record.get("proto", "-")
            conn_state = record.get("conn_state", "-")

            extra = {
                "uid": record.get("uid", "-"),
                "proto": proto,
                "service": service if service != "-" else None,
                "conn_state": conn_state,
                "orig_bytes": record.get("orig_bytes", "-"),
                "resp_bytes": record.get("resp_bytes", "-"),
                "duration": record.get("duration", "-"),
            }

            events.append(LogEvent(
                timestamp=timestamp,
                event_type="NETWORK_CONN",
                source_format="zeek",
                raw=line,
                source_ip=src_ip,
                dest_ip=dst_ip,
                dest_port=dst_port,
                extra=extra,
            ))

    return events
