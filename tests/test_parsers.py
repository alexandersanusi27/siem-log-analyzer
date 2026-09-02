"""
Unit tests for log parsers.

Run with:  pytest tests/ -v
"""
import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.ssh import parse_ssh_log
from parsers.windows import parse_windows_log
from parsers.nginx import parse_nginx_log


# ---------------------------------------------------------------------------
# SSH parser
# ---------------------------------------------------------------------------

class TestSSHParser:
    def _write_log(self, lines):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
        f.write("\n".join(lines))
        f.close()
        return f.name

    def test_parse_failed_password(self):
        path = self._write_log([
            "Jan 15 10:00:00 web01 sshd[1234]: Failed password for root from 1.2.3.4 port 12345 ssh2"
        ])
        events = parse_ssh_log(path)
        assert len(events) == 1
        assert events[0].event_type == "AUTH_FAILURE"
        assert events[0].source_ip == "1.2.3.4"
        assert events[0].username == "root"
        assert events[0].hostname == "web01"

    def test_parse_invalid_user(self):
        path = self._write_log([
            "Jan 15 10:00:01 web01 sshd[1234]: Invalid user admin from 5.6.7.8"
        ])
        events = parse_ssh_log(path)
        assert len(events) == 1
        assert events[0].event_type == "AUTH_FAILURE"
        assert events[0].username == "admin"

    def test_parse_accepted_password(self):
        path = self._write_log([
            "Jan 15 10:01:00 web01 sshd[1235]: Accepted password for alice from 9.10.11.12 port 54321 ssh2"
        ])
        events = parse_ssh_log(path)
        assert len(events) == 1
        assert events[0].event_type == "AUTH_SUCCESS"
        assert events[0].username == "alice"
        assert events[0].source_ip == "9.10.11.12"

    def test_parse_accepted_publickey(self):
        path = self._write_log([
            "Jan 15 10:02:00 web01 sshd[1236]: Accepted publickey for deploy from 1.1.1.1 port 11111 ssh2"
        ])
        events = parse_ssh_log(path)
        assert len(events) == 1
        assert events[0].event_type == "AUTH_SUCCESS"

    def test_parse_sudo_command(self):
        path = self._write_log([
            "Jan 15 10:03:00 web01 sudo:  bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"
        ])
        events = parse_ssh_log(path)
        assert len(events) == 1
        assert events[0].event_type == "SUDO"
        assert events[0].username == "bob"
        assert events[0].extra["target_user"] == "root"
        assert events[0].extra["command"] == "/bin/bash"

    def test_parse_su_success(self):
        path = self._write_log([
            "Jan 15 10:04:00 web01 su[1237]: Successful su for root by alice"
        ])
        events = parse_ssh_log(path)
        assert len(events) == 1
        assert events[0].event_type == "SU"
        assert events[0].username == "alice"
        assert events[0].extra["target_user"] == "root"

    def test_invalid_lines_skipped(self):
        path = self._write_log([
            "not a valid log line",
            "",
            "Jan 15 10:00:00 web01 sshd[1234]: Failed password for root from 1.2.3.4 port 12345 ssh2",
            "another garbage line",
        ])
        events = parse_ssh_log(path)
        assert len(events) == 1

    def test_multiple_events(self):
        path = self._write_log([
            "Jan 15 10:00:00 web01 sshd[100]: Failed password for root from 1.2.3.4 port 10001 ssh2",
            "Jan 15 10:00:01 web01 sshd[101]: Failed password for root from 1.2.3.4 port 10002 ssh2",
            "Jan 15 10:00:02 web01 sshd[102]: Accepted password for alice from 5.5.5.5 port 20000 ssh2",
        ])
        events = parse_ssh_log(path)
        assert len(events) == 3
        failures = [e for e in events if e.event_type == "AUTH_FAILURE"]
        successes = [e for e in events if e.event_type == "AUTH_SUCCESS"]
        assert len(failures) == 2
        assert len(successes) == 1


# ---------------------------------------------------------------------------
# Windows parser
# ---------------------------------------------------------------------------

class TestWindowsParser:
    def _write_json(self, data):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(data, f)
        f.close()
        return f.name

    def test_parse_4625_failed_logon(self):
        path = self._write_json([{
            "EventID": 4625,
            "TimeCreated": "2024-01-15T10:00:00",
            "Computer": "DC01",
            "TargetUserName": "administrator",
            "IpAddress": "1.2.3.4",
            "LogonType": 3,
            "FailureReason": "Bad password",
        }])
        events = parse_windows_log(path)
        assert len(events) == 1
        assert events[0].event_type == "AUTH_FAILURE"
        assert events[0].source_ip == "1.2.3.4"
        assert events[0].hostname == "DC01"

    def test_parse_4624_success(self):
        path = self._write_json([{
            "EventID": 4624,
            "TimeCreated": "2024-01-15T10:01:00",
            "Computer": "WS01",
            "TargetUserName": "jsmith",
            "IpAddress": "10.0.0.5",
            "LogonType": 3,
        }])
        events = parse_windows_log(path)
        assert len(events) == 1
        assert events[0].event_type == "AUTH_SUCCESS"

    def test_parse_4672_priv_assigned(self):
        path = self._write_json([{
            "EventID": 4672,
            "TimeCreated": "2024-01-15T10:02:00",
            "Computer": "DC01",
            "SubjectUserName": "administrator",
            "PrivilegeList": ["SeDebugPrivilege", "SeTcbPrivilege"],
        }])
        events = parse_windows_log(path)
        assert len(events) == 1
        assert events[0].event_type == "PRIV_ASSIGNED"
        assert "SeDebugPrivilege" in events[0].extra["privileges"]

    def test_parse_4720_account_created(self):
        path = self._write_json([{
            "EventID": 4720,
            "TimeCreated": "2024-01-15T10:03:00",
            "Computer": "DC01",
            "TargetUserName": "newuser",
            "SubjectUserName": "administrator",
        }])
        events = parse_windows_log(path)
        assert len(events) == 1
        assert events[0].event_type == "ACCOUNT_CREATED"

    def test_local_ip_stripped(self):
        path = self._write_json([{
            "EventID": 4625,
            "TimeCreated": "2024-01-15T10:00:00",
            "Computer": "DC01",
            "TargetUserName": "admin",
            "IpAddress": "::1",
            "LogonType": 2,
        }])
        events = parse_windows_log(path)
        assert events[0].source_ip is None

    def test_unknown_event_ids_skipped(self):
        path = self._write_json([
            {"EventID": 9999, "TimeCreated": "2024-01-15T10:00:00", "Computer": "DC01"},
            {"EventID": 4624, "TimeCreated": "2024-01-15T10:01:00", "Computer": "DC01",
             "TargetUserName": "user1", "IpAddress": "1.2.3.4", "LogonType": 3},
        ])
        events = parse_windows_log(path)
        assert len(events) == 1


# ---------------------------------------------------------------------------
# nginx parser
# ---------------------------------------------------------------------------

class TestNginxParser:
    def _write_log(self, lines):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
        f.write("\n".join(lines))
        f.close()
        return f.name

    def test_parse_get_request(self):
        path = self._write_log([
            '1.2.3.4 - - [15/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        ])
        events = parse_nginx_log(path)
        assert len(events) == 1
        assert events[0].event_type == "HTTP_REQUEST"
        assert events[0].source_ip == "1.2.3.4"
        assert events[0].extra["method"] == "GET"
        assert events[0].extra["status"] == 200

    def test_parse_authenticated_user(self):
        path = self._write_log([
            '1.2.3.4 - alice [15/Jan/2024:10:00:00 +0000] "GET /dashboard HTTP/1.1" 200 2048 "-" "Mozilla/5.0"'
        ])
        events = parse_nginx_log(path)
        assert events[0].username == "alice"

    def test_parse_post_request(self):
        path = self._write_log([
            '5.6.7.8 - - [15/Jan/2024:10:01:00 +0000] "POST /api/login HTTP/1.1" 401 128 "-" "curl/7.68.0"'
        ])
        events = parse_nginx_log(path)
        assert events[0].extra["method"] == "POST"
        assert events[0].extra["status"] == 401

    def test_invalid_lines_skipped(self):
        path = self._write_log([
            "not a log line",
            '1.2.3.4 - - [15/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        ])
        events = parse_nginx_log(path)
        assert len(events) == 1
