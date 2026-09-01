"""
Parser for Windows Event Logs exported as JSON.

Relevant Event IDs:
  4624 - Successful logon
  4625 - Failed logon
  4648 - Logon using explicit credentials
  4672 - Special privileges assigned to new logon
  4688 - Process creation
  4720 - User account created
  4728 - Member added to security-enabled global group
  4732 - Member added to security-enabled local group
  4771 - Kerberos pre-authentication failed
  4776 - Credential validation
"""
import json
from datetime import datetime
from typing import List
from models import LogEvent

LOGON_TYPES = {
    2: "Interactive", 3: "Network", 4: "Batch", 5: "Service",
    7: "Unlock", 8: "NetworkCleartext", 9: "NewCredentials",
    10: "RemoteInteractive", 11: "CachedInteractive",
}

EVENT_TYPE_MAP = {
    4624: "AUTH_SUCCESS",
    4625: "AUTH_FAILURE",
    4648: "EXPLICIT_CRED",
    4672: "PRIV_ASSIGNED",
    4688: "PROCESS_CREATE",
    4720: "ACCOUNT_CREATED",
    4728: "GROUP_MEMBER_ADD",
    4732: "LOCAL_GROUP_ADD",
    4771: "PRE_AUTH_FAIL",
    4776: "CRED_VALIDATE",
}

_LOCAL_IPS = {"-", "::1", "127.0.0.1", ""}


def _parse_ts(ts_str: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts_str.split("+")[0].split("Z")[0], fmt)
        except (ValueError, AttributeError):
            continue
    return datetime.now()


def parse_windows_log(filepath: str) -> List[LogEvent]:
    with open(filepath, "r", errors="replace") as fh:
        data = json.load(fh)

    events: List[LogEvent] = []
    for entry in data:
        event_id = entry.get("EventID")
        event_type = EVENT_TYPE_MAP.get(event_id)
        if not event_type:
            continue

        timestamp = _parse_ts(entry.get("TimeCreated", ""))

        source_ip = entry.get("IpAddress") or entry.get("SourceAddress")
        if source_ip in _LOCAL_IPS or source_ip is None:
            source_ip = None

        username = entry.get("TargetUserName") or entry.get("SubjectUserName")
        if username in ("-", "SYSTEM", "", None):
            username = None

        hostname = entry.get("Computer") or entry.get("WorkstationName")

        extra: dict = {"event_id": event_id}
        if "LogonType" in entry:
            lt = entry["LogonType"]
            extra["logon_type"] = LOGON_TYPES.get(lt, str(lt))
            extra["logon_type_id"] = lt
        if "PrivilegeList" in entry:
            extra["privileges"] = entry["PrivilegeList"]
        if "ProcessName" in entry:
            extra["process"] = entry["ProcessName"]
        if "CommandLine" in entry:
            extra["command_line"] = entry["CommandLine"]
        if "FailureReason" in entry:
            extra["failure_reason"] = entry["FailureReason"]

        events.append(LogEvent(
            timestamp=timestamp,
            event_type=event_type,
            source_format="windows",
            raw=json.dumps(entry),
            source_ip=source_ip,
            username=username,
            hostname=hostname,
            extra=extra,
        ))

    return events
