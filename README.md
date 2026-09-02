# siem-log-analyzer

Built this as a personal project while studying for my security modules. Wanted to actually understand what SOC work looks like in practice rather than just reading theory, so I decided to build a log analysis tool from scratch.

The idea is simple — point it at log files, and it tells you what looks suspicious. It parses SSH logs, Windows Event Logs, Zeek network logs and nginx access logs, then runs them through detection rules and gives you a ranked list of alerts.

---

## what it detects

| detector | what it does |
|---|---|
| **Brute Force** | lots of failed logins from one IP in a short window. if a successful login follows — that's a compromise |
| **Lateral Movement** | one IP logging into multiple internal servers in a short time, or scanning admin ports (SSH, RDP, SMB) |
| **Privilege Escalation** | sudo/su to root, sketchy Windows privilege grants (EventID 4672), new accounts being created |
| **Impossible Travel** | same user logs in from two countries within minutes — physically impossible, likely stolen creds |
| **Off-Hours Login** | successful logins at 2-5am or weekends, worse if the IP is external |
| **Credential Stuffing** | loads of different usernames tried from one IP with only 1-2 attempts each. stays under the brute force radar on purpose |
| **Data Exfiltration** | unusually large outbound transfers to external IPs picked up from Zeek logs |
| **Web Attacks** | SQLi payloads, XSS attempts, path traversal, known scanner tools (sqlmap, nikto, dirbuster), directory brute forcing |

Something that surprised me — credential stuffing and brute force look completely different in logs. Brute force is obvious and noisy (same username, 100s of attempts). Stuffing is quiet and easy to miss (50 different usernames, tried once each). Had to write separate logic for both.

---

## supported log formats

- Linux SSH `auth.log` (sshd failed/accepted, sudo, su)
- Windows Event Log exported as JSON (4624, 4625, 4672, 4720 etc.)
- Zeek `conn.log` — network flow data
- nginx / Apache combined access log

---

## how to run it

```bash
pip install -r requirements.txt

# easiest way to try it — uses the included sample logs
python main.py --demo

# point at your own logs
python main.py --ssh /var/log/auth.log
python main.py --ssh auth.log --windows events.json --zeek conn.log --nginx access.log

# only show high severity stuff
python main.py --ssh auth.log --min-severity HIGH

# different output formats
python main.py --demo --output json > alerts.json
python main.py --demo --output csv > alerts.csv
python main.py --demo --output html    # generates a dark mode HTML report file

# live mode — watches a log file and prints alerts as new lines come in
python main.py --ssh /var/log/auth.log --watch

# run specific detectors only
python main.py --ssh auth.log --detectors brute_force credential_stuffing impossible_travel
```

---

## demo

Running `python main.py --demo` on the sample logs I put together:

```
Loading logs...
  [ssh]       111 events  <- sample_logs/auth.log
  [windows]    37 events  <- sample_logs/windows_events.json
  [zeek]       27 events  <- sample_logs/zeek_conn.log
  [nginx]      46 events  <- sample_logs/nginx_access.log
  Total events loaded: 221

Running detectors...
  [Brute Force] 6 alert(s)
  [Lateral Movement] 2 alert(s)
  [Privilege Escalation] 4 alert(s)
  [Impossible Travel] 1 alert(s)
  [Off Hours] 3 alert(s)
  [Credential Stuffing] 1 alert(s)
  [Data Exfiltration] 1 alert(s)
  [Web Attacks] 6 alert(s)
  Alerts after severity filter (>= LOW): 24

  CRITICAL: 4  |  HIGH: 8  |  MEDIUM: 6  |  LOW: 6
```

The sample logs are crafted to hit every detector — a brute force that ends with a successful login (compromise), the same user logging in from Germany and California 4 minutes apart, 350MB sent to an IP in Beijing, SQLi via sqlmap etc.

---

## tests

```bash
pytest tests/ -v
```

49 tests, all passing. Covers the parsers and all 8 detectors including edge cases like events that fall outside the detection window, private IPs being ignored by the geo lookup, and making sure brute force isn't misclassified as credential stuffing.

---

## project layout

```
├── main.py
├── models.py              # LogEvent and Alert dataclasses
├── parsers/               # one file per log format
├── detectors/             # one file per detection rule
├── dashboard/             # terminal output + HTML report
├── utils/geoip.py         # IP lookup + haversine distance for impossible travel
├── sample_logs/           # test logs that trigger all 8 detectors
└── tests/
```

Adding a new parser = one file in `parsers/` with a `parse_X_log(filepath)` function.
Adding a detector = one file in `detectors/` with a `detect(events)` function, gets picked up automatically.

---

## dependencies

- Python 3.9+
- `rich` for the terminal UI
- `pytest` for tests

GeoIP uses a hardcoded table for the sample logs (offline, no key needed). For real IPs it calls ip-api.com and caches the results so it doesn't spam the API.

---

MIT
