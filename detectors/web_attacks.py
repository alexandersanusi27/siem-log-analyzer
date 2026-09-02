"""
Web Attack Detector — MITRE ATT&CK T1190, T1059, T1083

Analyses HTTP_REQUEST events (from nginx/Apache logs) for:
  1. SQL Injection patterns in URL path/query
  2. Cross-Site Scripting (XSS) payloads
  3. Path traversal / LFI attempts
  4. Known vulnerability scanner user agents
  5. Error-rate spike — rapid 4xx/5xx responses (directory enumeration)
"""
import re
from collections import defaultdict
from datetime import timedelta
from typing import List, Optional, Tuple

from models import Alert, LogEvent

# ---------------------------------------------------------------------------
# Attack pattern libraries
# ---------------------------------------------------------------------------

_SQLI = [
    re.compile(r"(?i)(\%27|')(\s*)(or|and)\s"),
    re.compile(r"(?i)union(\s+)(all\s+)?select"),
    re.compile(r"(?i)(drop|truncate|delete)\s+(table|database|from)"),
    re.compile(r"(?i)(exec|execute)\s*\(|xp_cmdshell|sp_executesql"),
    re.compile(r"(?i)waitfor\s+delay|sleep\s*\(\s*\d"),
    re.compile(r"(?i)information_schema|sys\.(tables|columns)|sysobjects"),
    re.compile(r"(?i)convert\s*\(|cast\s*\(.*\bselect\b"),
    re.compile(r"--\s*$|;--|\s#\s*$"),
]

_XSS = [
    re.compile(r"(?i)<\s*script[\s/>]"),
    re.compile(r"(?i)javascript\s*:"),
    re.compile(r"(?i)on(error|load|click|focus|mouseover|submit)\s*="),
    re.compile(r"(?i)alert\s*\(|confirm\s*\(|prompt\s*\("),
    re.compile(r"(?i)document\.(cookie|write|location)"),
    re.compile(r"(?i)<\s*iframe[\s/>]"),
    re.compile(r"(?i)eval\s*\(|fromcharcode|atob\s*\("),
    re.compile(r"(?i)%3cscript|%3c%2fscript"),
]

_PATH_TRAVERSAL = [
    re.compile(r"(\.\./){2,}|(\.\.\\/){2,}"),
    re.compile(r"\.\.%2[fF]|\.\.%5[cC]"),
    re.compile(r"(?i)/etc/(passwd|shadow|hosts|sudoers|crontab)"),
    re.compile(r"(?i)/proc/(self|version|cmdline|environ)"),
    re.compile(r"(?i)(boot\.ini|win\.ini|system32)"),
    re.compile(r"(?i)/\.(git|env|htpasswd|htaccess|bash_history|ssh/id_rsa)"),
    re.compile(r"%00"),  # null byte
]

_SCANNER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "dirb",
    "gobuster", "wfuzz", "burpsuite", "zaproxy", "w3af", "acunetix",
    "nessus", "openvas", "metasploit", "nuclei", "hydra", "medusa",
    "zgrab", "shodan", "censys", "python-httpx", "go-http-client/1.1",
]

ERROR_THRESHOLD  = 20   # 4xx/5xx requests per window
ERROR_WINDOW_MIN = 3


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def detect(events: List[LogEvent]) -> List[Alert]:
    http_events = [e for e in events if e.event_type == "HTTP_REQUEST"]
    if not http_events:
        return []

    alerts: List[Alert] = []
    alerts.extend(_detect_payload_attacks(http_events))
    alerts.extend(_detect_scanners(http_events))
    alerts.extend(_detect_error_spike(http_events))
    return _deduplicate(alerts)


# ---------------------------------------------------------------------------
# Strategy 1 — payload inspection (SQLi / XSS / path traversal)
# ---------------------------------------------------------------------------

def _detect_payload_attacks(events: List[LogEvent]) -> List[Alert]:
    # Group suspicious requests by (ip, attack_type)
    hits: dict = defaultdict(list)

    for e in events:
        path = e.extra.get("path", "")
        ua   = e.extra.get("user_agent", "")
        target = path + " " + ua

        attack = _classify_payload(target)
        if attack:
            hits[(e.source_ip, attack)].append(e)

    alerts: List[Alert] = []
    for (ip, attack_type), evts in hits.items():
        evts.sort(key=lambda e: e.timestamp)

        if attack_type == "SQL_INJECTION":
            severity, score = "CRITICAL", 90
            mitre = "T1190 - Exploit Public-Facing Application (SQLi)"
            title = f"SQL Injection: {ip}"
        elif attack_type == "XSS":
            severity, score = "HIGH", 75
            mitre = "T1059.007 - JavaScript (XSS)"
            title = f"XSS Attempt: {ip}"
        else:  # PATH_TRAVERSAL
            severity, score = "HIGH", 80
            mitre = "T1083 - File and Directory Discovery (Path Traversal)"
            title = f"Path Traversal / LFI: {ip}"

        sample_paths = [e.extra.get("path", "") for e in evts[:3]]

        alerts.append(Alert(
            severity=severity,
            alert_type="WEB_ATTACK",
            title=title,
            description=(
                f"{attack_type.replace('_', ' ').title()} detected from {ip}. "
                f"{len(evts)} malicious request(s) targeting: "
                f"{', '.join(sample_paths[:2])}{'...' if len(evts) > 2 else ''}."
            ),
            score=score,
            first_seen=evts[0].timestamp,
            last_seen=evts[-1].timestamp,
            involved_ips=[ip],
            event_count=len(evts),
            details={
                "attack_subtype":   attack_type,
                "request_count":    len(evts),
                "sample_paths":     sample_paths,
                "http_methods":     sorted(set(e.extra.get("method") for e in evts)),
                "status_codes":     sorted(set(e.extra.get("status") for e in evts)),
            },
            mitre_technique=mitre,
        ))

    return alerts


def _classify_payload(text: str) -> Optional[str]:
    for pat in _SQLI:
        if pat.search(text):
            return "SQL_INJECTION"
    for pat in _XSS:
        if pat.search(text):
            return "XSS"
    for pat in _PATH_TRAVERSAL:
        if pat.search(text):
            return "PATH_TRAVERSAL"
    return None


# ---------------------------------------------------------------------------
# Strategy 2 — scanner user-agent detection
# ---------------------------------------------------------------------------

def _detect_scanners(events: List[LogEvent]) -> List[Alert]:
    # ip -> [(event, scanner_name)]
    scanner_hits: dict = defaultdict(list)

    for e in events:
        ua = (e.extra.get("user_agent") or "").lower()
        for scanner in _SCANNER_AGENTS:
            if scanner in ua:
                scanner_hits[e.source_ip].append((e, scanner))
                break

    alerts: List[Alert] = []
    for ip, hits in scanner_hits.items():
        hits.sort(key=lambda x: x[0].timestamp)
        evts    = [h[0] for h in hits]
        scanner = hits[0][1]  # primary scanner name

        alerts.append(Alert(
            severity="HIGH",
            alert_type="WEB_ATTACK",
            title=f"Vulnerability Scanner: {ip}",
            description=(
                f"Known vulnerability scanner '{scanner}' detected from {ip}. "
                f"{len(evts)} request(s) made — active reconnaissance in progress."
            ),
            score=80,
            first_seen=evts[0].timestamp,
            last_seen=evts[-1].timestamp,
            involved_ips=[ip],
            event_count=len(evts),
            details={
                "attack_subtype":  "SCANNER",
                "scanner_name":    scanner,
                "request_count":   len(evts),
                "sample_paths":    [e.extra.get("path") for e in evts[:5]],
                "status_codes":    sorted(set(e.extra.get("status") for e in evts)),
            },
            mitre_technique="T1595.002 - Active Scanning: Vulnerability Scanning",
        ))

    return alerts


# ---------------------------------------------------------------------------
# Strategy 3 — error spike (directory enumeration / fuzzing)
# ---------------------------------------------------------------------------

def _detect_error_spike(events: List[LogEvent]) -> List[Alert]:
    ip_errors: dict = defaultdict(list)
    for e in events:
        status = e.extra.get("status", 0)
        if 400 <= status < 600:
            ip_errors[e.source_ip].append(e)

    alerts: List[Alert] = []
    for ip, errs in ip_errors.items():
        errs.sort(key=lambda e: e.timestamp)

        win_start = 0
        max_count = 0
        best_window: List[LogEvent] = []

        for i in range(len(errs)):
            while (errs[i].timestamp - errs[win_start].timestamp) > timedelta(minutes=ERROR_WINDOW_MIN):
                win_start += 1
            if (i - win_start + 1) > max_count:
                max_count = i - win_start + 1
                best_window = errs[win_start : i + 1]

        if max_count < ERROR_THRESHOLD:
            continue

        unique_paths = set(e.extra.get("path", "").split("?")[0] for e in best_window)
        status_counts: dict = defaultdict(int)
        for e in best_window:
            status_counts[e.extra.get("status", 0)] += 1

        score    = min(100, 55 + len(unique_paths) // 2)
        severity = "HIGH" if len(unique_paths) >= 50 else "MEDIUM"

        alerts.append(Alert(
            severity=severity,
            alert_type="WEB_ATTACK",
            title=f"Directory Enumeration: {ip}",
            description=(
                f"Rapid error-rate spike from {ip}: {max_count} HTTP error responses "
                f"in {ERROR_WINDOW_MIN} minutes across {len(unique_paths)} unique paths. "
                f"Consistent with directory enumeration or fuzzing."
            ),
            score=score,
            first_seen=best_window[0].timestamp,
            last_seen=best_window[-1].timestamp,
            involved_ips=[ip],
            event_count=max_count,
            details={
                "attack_subtype":   "DIRECTORY_ENUMERATION",
                "error_count":      max_count,
                "unique_paths":     len(unique_paths),
                "status_breakdown": dict(status_counts),
                "window_minutes":   ERROR_WINDOW_MIN,
            },
            mitre_technique="T1595.003 - Active Scanning: Wordlist Scanning",
        ))

    return alerts


def _deduplicate(alerts: List[Alert]) -> List[Alert]:
    seen: set = set()
    out: List[Alert] = []
    for a in alerts:
        key = (a.alert_type, a.involved_ips[0] if a.involved_ips else "", a.details.get("attack_subtype", ""))
        if key not in seen:
            seen.add(key)
            out.append(a)
    return out
