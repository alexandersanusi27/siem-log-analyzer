"""
Parser for nginx / Apache Combined Log Format.

Log line format:
  $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"

Example:
  192.168.1.1 - alice [15/Jan/2024:10:00:00 +0000] "GET /index.php?id=1 HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
"""
import re
from datetime import datetime
from typing import List

from models import LogEvent

_PATTERN = re.compile(
    r'(\S+)\s+'                          # 1: client IP
    r'\S+\s+'                            # ident (always -)
    r'(\S+)\s+'                          # 2: auth user
    r'\[([^\]]+)\]\s+'                   # 3: timestamp
    r'"([A-Z]+)\s+([^ "]+)[^"]*"\s+'    # 4: method  5: path+query
    r'(\d{3})\s+'                        # 6: HTTP status
    r'(\d+|-)\s+'                        # 7: bytes (- if none)
    r'"([^"]*)"\s+'                      # 8: referer
    r'"([^"]*)"'                         # 9: user-agent
)


def _parse_ts(raw: str) -> datetime:
    # e.g. "15/Jan/2024:10:00:00 +0000"
    try:
        return datetime.strptime(raw.split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return datetime.now()


def parse_nginx_log(filepath: str) -> List[LogEvent]:
    events: List[LogEvent] = []

    with open(filepath, "r", errors="replace") as fh:
        for line in fh:
            line = line.rstrip()
            m = _PATTERN.match(line)
            if not m:
                continue

            ip, user, ts_raw, method, path, status, raw_bytes, referer, ua = m.groups()

            username = user if user != "-" else None
            try:
                status_code = int(status)
            except ValueError:
                status_code = 0
            try:
                bytes_sent = int(raw_bytes)
            except ValueError:
                bytes_sent = 0

            events.append(LogEvent(
                timestamp=_parse_ts(ts_raw),
                event_type="HTTP_REQUEST",
                source_format="nginx",
                raw=line,
                source_ip=ip,
                username=username,
                extra={
                    "method":     method,
                    "path":       path,
                    "status":     status_code,
                    "bytes_sent": bytes_sent,
                    "referer":    referer if referer != "-" else None,
                    "user_agent": ua,
                },
            ))

    return events
