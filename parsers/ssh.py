"""
Parser for Linux/Unix SSH auth.log files.

Handles these sshd log line formats:
  Failed password for [invalid user] <user> from <ip> port <port> ssh2
  Accepted password/publickey for <user> from <ip> port <port> ssh2
  Invalid user <user> from <ip>
  sudo: <user> : TTY=... ; USER=<target> ; COMMAND=<cmd>
  su[pid]: Successful su for <target> by <user>
"""
import re
from datetime import datetime
from typing import List
from models import LogEvent

# --- Regex patterns ---

SSHD_FAILED = re.compile(
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(\S+) from (\S+) port \d+"
)
SSHD_INVALID = re.compile(
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[\d+\]:\s+"
    r"Invalid user (\S+) from (\S+)"
)
SSHD_ACCEPTED = re.compile(
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[\d+\]:\s+"
    r"Accepted \S+ for (\S+) from (\S+) port \d+"
)
SUDO_CMD = re.compile(
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sudo:\s+(\S+)\s+:\s+"
    r"TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.+)"
)
SU_SUCCESS = re.compile(
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+su\[\d+\]:\s+"
    r"Successful su for (\S+) by (\S+)"
)


def _parse_ts(raw_ts: str, year: int) -> datetime:
    try:
        return datetime.strptime(f"{year} {raw_ts.strip()}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return datetime.now()


def parse_ssh_log(filepath: str) -> List[LogEvent]:
    events: List[LogEvent] = []
    year = datetime.now().year

    with open(filepath, "r", errors="replace") as fh:
        for line in fh:
            line = line.rstrip()

            m = SSHD_FAILED.match(line)
            if m:
                events.append(LogEvent(
                    timestamp=_parse_ts(m.group(1), year),
                    event_type="AUTH_FAILURE",
                    source_format="ssh",
                    raw=line,
                    hostname=m.group(2),
                    username=m.group(3),
                    source_ip=m.group(4),
                ))
                continue

            m = SSHD_INVALID.match(line)
            if m:
                events.append(LogEvent(
                    timestamp=_parse_ts(m.group(1), year),
                    event_type="AUTH_FAILURE",
                    source_format="ssh",
                    raw=line,
                    hostname=m.group(2),
                    username=m.group(3),
                    source_ip=m.group(4),
                ))
                continue

            m = SSHD_ACCEPTED.match(line)
            if m:
                events.append(LogEvent(
                    timestamp=_parse_ts(m.group(1), year),
                    event_type="AUTH_SUCCESS",
                    source_format="ssh",
                    raw=line,
                    hostname=m.group(2),
                    username=m.group(3),
                    source_ip=m.group(4),
                ))
                continue

            m = SUDO_CMD.match(line)
            if m:
                events.append(LogEvent(
                    timestamp=_parse_ts(m.group(1), year),
                    event_type="SUDO",
                    source_format="ssh",
                    raw=line,
                    hostname=m.group(2),
                    username=m.group(3),
                    extra={
                        "target_user": m.group(4),
                        "command": m.group(5).strip(),
                    },
                ))
                continue

            m = SU_SUCCESS.match(line)
            if m:
                events.append(LogEvent(
                    timestamp=_parse_ts(m.group(1), year),
                    event_type="SU",
                    source_format="ssh",
                    raw=line,
                    hostname=m.group(2),
                    username=m.group(4),   # the user who ran su
                    extra={"target_user": m.group(3)},
                ))
                continue

    return events
