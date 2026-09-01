"""
Privilege Escalation Detector — MITRE ATT&CK T1548, T1134, T1136

Detects:
  - Linux sudo/su usage (especially to root with high-risk commands)
  - Windows dangerous privilege assignment (EventID 4672)
  - New account creation (EventID 4720)
"""
from typing import List

from models import Alert, LogEvent

# Commands that warrant a higher risk rating when run via sudo
HIGH_RISK_COMMANDS = {
    "/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash",
    "chmod", "chown", "passwd", "adduser", "useradd",
    "visudo", "crontab", "at", "systemctl", "service",
    "nc", "ncat", "netcat", "python", "python3", "perl", "ruby",
    "wget", "curl", "bash", "sh",
}

# Windows privileges that indicate elevated / dangerous access
DANGEROUS_WIN_PRIVS = {
    "SeDebugPrivilege",
    "SeTcbPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
}


def detect(events: List[LogEvent]) -> List[Alert]:
    alerts: List[Alert] = []

    for e in events:
        if e.event_type == "SUDO":
            alerts.extend(_handle_sudo(e))

        elif e.event_type == "SU":
            alerts.extend(_handle_su(e))

        elif e.event_type == "PRIV_ASSIGNED":
            alerts.extend(_handle_priv_assigned(e))

        elif e.event_type == "ACCOUNT_CREATED":
            alerts.extend(_handle_account_created(e))

    return alerts


def _handle_sudo(e: LogEvent) -> List[Alert]:
    username = e.username or "unknown"
    target = e.extra.get("target_user", "root")
    command = e.extra.get("command", "")
    cmd_base = command.split()[0] if command.split() else ""

    is_high_risk = cmd_base in HIGH_RISK_COMMANDS or any(
        kw in command for kw in HIGH_RISK_COMMANDS
    )
    to_root = target == "root"

    if to_root and is_high_risk:
        severity, score = "HIGH", 80
    elif to_root:
        severity, score = "MEDIUM", 55
    else:
        severity, score = "LOW", 30

    return [Alert(
        severity=severity,
        alert_type="PRIVILEGE_ESCALATION",
        title=f"Sudo Escalation: {username} -> {target}",
        description=(
            f"User '{username}' ran sudo as '{target}': {command}"
            + (" [HIGH-RISK COMMAND]" if is_high_risk else "")
        ),
        score=score,
        first_seen=e.timestamp,
        last_seen=e.timestamp,
        involved_users=[username],
        event_count=1,
        details={
            "command": command,
            "target_user": target,
            "hostname": e.hostname,
            "high_risk_command": is_high_risk,
        },
        mitre_technique="T1548.003 - Sudo and Sudo Caching",
    )]


def _handle_su(e: LogEvent) -> List[Alert]:
    username = e.username or "unknown"
    target = e.extra.get("target_user", "root")
    to_root = target == "root"

    severity, score = ("HIGH", 70) if to_root else ("MEDIUM", 45)

    return [Alert(
        severity=severity,
        alert_type="PRIVILEGE_ESCALATION",
        title=f"su Escalation: {username} -> {target}",
        description=f"User '{username}' switched to '{target}' via su.",
        score=score,
        first_seen=e.timestamp,
        last_seen=e.timestamp,
        involved_users=[username],
        event_count=1,
        details={"target_user": target, "hostname": e.hostname},
        mitre_technique="T1548.003 - Sudo and Sudo Caching",
    )]


def _handle_priv_assigned(e: LogEvent) -> List[Alert]:
    username = e.username or "unknown"
    privs = e.extra.get("privileges", [])
    dangerous = [p for p in privs if p in DANGEROUS_WIN_PRIVS]

    if not dangerous:
        return []

    return [Alert(
        severity="HIGH",
        alert_type="PRIVILEGE_ESCALATION",
        title=f"Dangerous Privileges Assigned: {username}",
        description=(
            f"Account '{username}' on {e.hostname} was granted dangerous Windows privileges: "
            f"{', '.join(dangerous)}"
        ),
        score=75,
        first_seen=e.timestamp,
        last_seen=e.timestamp,
        involved_users=[username],
        event_count=1,
        details={
            "dangerous_privileges": dangerous,
            "all_privileges": privs,
            "hostname": e.hostname,
            "event_id": e.extra.get("event_id"),
        },
        mitre_technique="T1134 - Access Token Manipulation",
    )]


def _handle_account_created(e: LogEvent) -> List[Alert]:
    username = e.username or "unknown"

    return [Alert(
        severity="MEDIUM",
        alert_type="PRIVILEGE_ESCALATION",
        title=f"New Account Created: {username}",
        description=f"A new user account '{username}' was created on {e.hostname}.",
        score=60,
        first_seen=e.timestamp,
        last_seen=e.timestamp,
        involved_users=[username],
        event_count=1,
        details={
            "hostname": e.hostname,
            "event_id": e.extra.get("event_id"),
        },
        mitre_technique="T1136 - Create Account",
    )]
