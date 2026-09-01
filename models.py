from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class LogEvent:
    timestamp: datetime
    event_type: str       # AUTH_FAILURE, AUTH_SUCCESS, SUDO, SU, PRIV_ASSIGNED, NETWORK_CONN, etc.
    source_format: str    # 'ssh', 'windows', 'zeek'
    raw: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW
    alert_type: str        # BRUTE_FORCE, LATERAL_MOVEMENT, PRIVILEGE_ESCALATION, IMPOSSIBLE_TRAVEL
    title: str
    description: str
    score: int             # 0-100 risk score
    first_seen: datetime
    last_seen: datetime
    involved_ips: List[str] = field(default_factory=list)
    involved_users: List[str] = field(default_factory=list)
    event_count: int = 0
    details: Dict[str, Any] = field(default_factory=dict)
    mitre_technique: Optional[str] = None
