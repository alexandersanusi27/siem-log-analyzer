# SIEM Log Analyzer

A Python-based SIEM (Security Information and Event Management) tool that ingests real-world log formats and detects active threats using rule-based detection logic. Built to demonstrate SOC analyst / security engineering skills.

## What it detects

| Detection | Description | MITRE ATT&CK |
|---|---|---|
| **Brute Force** | High-volume failed logins from a single IP, with escalation if a success follows | T1110 |
| **Lateral Movement** | Single source IP authenticating to many internal hosts; admin-port scanning (Zeek) | T1021, T1046 |
| **Privilege Escalation** | `sudo`/`su` to root, dangerous Windows privilege assignment (4672), new account creation | T1548, T1134, T1136 |
| **Impossible Travel** | Same user logging in from geographically distant IPs faster than aircraft speed | T1078 |

## Log formats supported

- **SSH auth.log** — standard Linux `/var/log/auth.log` (sshd, sudo, su)
- **Windows Event Log** — JSON export (EventIDs: 4624, 4625, 4672, 4688, 4720, and more)
- **Zeek conn.log** — tab-separated network connection logs

## Output formats

- **Terminal** — colour-coded ranked alert dashboard with detail panels (default)
- **JSON** — machine-readable, for piping into other tools
- **CSV** — for importing into spreadsheets or SIEMs

## Quick start

```bash
git clone https://github.com/YOUR_USERNAME/siem-log-analyzer
cd siem-log-analyzer
pip install -r requirements.txt

# Run on bundled sample logs (triggers all 4 detectors)
python main.py --demo

# Run on your own logs
python main.py --ssh /var/log/auth.log
python main.py --windows events.json --zeek conn.log
python main.py --ssh auth.log --min-severity HIGH
python main.py --ssh auth.log --output json > alerts.json
python main.py --ssh auth.log --output csv > alerts.csv

# Run only specific detectors
python main.py --ssh auth.log --detectors brute_force impossible_travel
```

## Sample output (--demo)

```
Loading logs...
  [ssh]        94 events  <- sample_logs/auth.log
  [windows]    37 events  <- sample_logs/windows_events.json
  [zeek]       24 events  <- sample_logs/zeek_conn.log
  Total events loaded: 155

Running detectors...
  [Brute Force] 5 alert(s)
  [Lateral Movement] 2 alert(s)
  [Privilege Escalation] 4 alert(s)
  [Impossible Travel] 1 alert(s)
  Alerts after severity filter (>= LOW): 12

  SIEM LOG ANALYZER | Alert Dashboard

  Summary
  -------
  Alerts found:    12
  Breakdown:       CRITICAL: 4  HIGH: 4  MEDIUM: 4
  Events parsed:   SSH: 94  WINDOWS: 37  ZEEK: 24 (total 155)

  Ranked Alerts
  #  Severity  Type                   Score  Source IPs       Users     Events  Title
  1  CRITICAL  Brute Force            100    203.0.113.50     root      65      Brute Force: 203.0.113.50
  2  CRITICAL  Impossible Travel      100    185.220.101.45   alice     2       Impossible Travel: alice
  3  CRITICAL  Brute Force             90    203.0.113.51     admin     22      Brute Force: 203.0.113.51
  4  CRITICAL  Lateral Movement        80    192.168.1.100    sysadmin  6       Lateral Movement (Auth): 192.168.1.100
  ...
```

## Project structure

```
siem-log-analyzer/
├── main.py                     # CLI entry point
├── models.py                   # LogEvent and Alert dataclasses
├── parsers/
│   ├── ssh.py                  # auth.log parser
│   ├── windows.py              # Windows Event Log JSON parser
│   └── zeek.py                 # Zeek conn.log parser
├── detectors/
│   ├── brute_force.py
│   ├── lateral_movement.py
│   ├── privilege_escalation.py
│   └── impossible_travel.py
├── dashboard/
│   └── terminal.py             # Rich terminal UI
├── utils/
│   └── geoip.py                # IP geolocation (offline table + ip-api.com)
└── sample_logs/
    ├── auth.log                 # Synthetic SSH log (triggers all detectors)
    ├── windows_events.json      # Windows Event Log sample
    └── zeek_conn.log            # Zeek network log sample
```

## Requirements

- Python 3.9+
- [`rich`](https://github.com/Textualize/rich) (terminal rendering)

GeoIP lookups for impossible travel use the built-in IP table (covers all sample logs, no API key needed). For real-world IPs, the tool queries [ip-api.com](http://ip-api.com) and caches results locally.

## Extending

**Add a new log format:** create `parsers/myformat.py` with a `parse_myformat_log(filepath) -> List[LogEvent]` function and hook it into `main.py`.

**Add a new detector:** create `detectors/mydetector.py` with a `detect(events: List[LogEvent]) -> List[Alert]` function. It is automatically available via `--detectors mydetector`.

## License

MIT
