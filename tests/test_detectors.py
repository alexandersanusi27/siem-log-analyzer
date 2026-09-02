"""
Unit tests for all detectors.

Run with:  pytest tests/ -v
"""
import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import LogEvent, Alert
from detectors import (
    brute_force,
    lateral_movement,
    privilege_escalation,
    impossible_travel,
    off_hours,
    credential_stuffing,
    data_exfiltration,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(
    event_type="AUTH_FAILURE",
    source_ip="1.2.3.4",
    username="root",
    hostname="server1",
    source_format="ssh",
    offset_seconds=0,
    base_time=None,
    extra=None,
    dest_ip=None,
    dest_port=None,
):
    if base_time is None:
        base_time = datetime(2024, 1, 15, 10, 0, 0)
    return LogEvent(
        timestamp=base_time + timedelta(seconds=offset_seconds),
        event_type=event_type,
        source_format=source_format,
        raw="",
        source_ip=source_ip,
        username=username,
        hostname=hostname,
        dest_ip=dest_ip,
        dest_port=dest_port,
        extra=extra or {},
    )


# ---------------------------------------------------------------------------
# Brute force
# ---------------------------------------------------------------------------

class TestBruteForce:
    def test_no_alert_below_threshold(self):
        events = [_make_event(offset_seconds=i * 10) for i in range(4)]
        assert brute_force.detect(events) == []

    def test_medium_alert_at_threshold(self):
        events = [_make_event(offset_seconds=i * 5) for i in range(5)]
        alerts = brute_force.detect(events)
        assert len(alerts) == 1
        assert alerts[0].severity == "MEDIUM"
        assert alerts[0].alert_type == "BRUTE_FORCE"

    def test_critical_alert_large_burst(self):
        events = [_make_event(offset_seconds=i * 3) for i in range(55)]
        alerts = brute_force.detect(events)
        assert len(alerts) == 1
        assert alerts[0].severity == "CRITICAL"
        assert alerts[0].event_count >= 50

    def test_compromise_escalation(self):
        # 25 failures followed by success from same IP
        failures = [_make_event(offset_seconds=i * 5) for i in range(25)]
        success  = _make_event(event_type="AUTH_SUCCESS", offset_seconds=130)
        alerts   = brute_force.detect(failures + [success])
        assert any(a.details.get("successful_compromise") for a in alerts)
        assert any(a.severity == "CRITICAL" for a in alerts)

    def test_separate_ips_produce_separate_alerts(self):
        events = (
            [_make_event(source_ip="1.1.1.1", offset_seconds=i * 5) for i in range(10)]
            + [_make_event(source_ip="2.2.2.2", offset_seconds=i * 5) for i in range(10)]
        )
        alerts = brute_force.detect(events)
        ips = [a.involved_ips[0] for a in alerts]
        assert "1.1.1.1" in ips
        assert "2.2.2.2" in ips

    def test_events_outside_window_not_counted(self):
        # 3 failures now, 3 failures 20 minutes later — should not combine into one burst
        early = [_make_event(offset_seconds=i * 10) for i in range(3)]
        late  = [_make_event(offset_seconds=1200 + i * 10) for i in range(3)]
        alerts = brute_force.detect(early + late)
        assert alerts == []  # neither batch reaches threshold of 5


# ---------------------------------------------------------------------------
# Lateral movement
# ---------------------------------------------------------------------------

class TestLateralMovement:
    def test_no_alert_below_host_threshold(self):
        events = [
            _make_event(event_type="AUTH_SUCCESS", hostname=f"server{i}", offset_seconds=i * 60)
            for i in range(2)
        ]
        alerts = lateral_movement.detect(events)
        auth_alerts = [a for a in alerts if "Auth" in a.title]
        assert auth_alerts == []

    def test_alert_triggered_at_threshold(self):
        events = [
            _make_event(event_type="AUTH_SUCCESS", hostname=f"server{i}", offset_seconds=i * 60)
            for i in range(3)
        ]
        alerts = lateral_movement.detect(events)
        assert any(a.alert_type == "LATERAL_MOVEMENT" for a in alerts)

    def test_host_count_in_details(self):
        events = [
            _make_event(event_type="AUTH_SUCCESS", hostname=f"host{i}", offset_seconds=i * 60)
            for i in range(5)
        ]
        alerts = lateral_movement.detect(events)
        lm = next(a for a in alerts if a.alert_type == "LATERAL_MOVEMENT")
        assert lm.details["host_count"] == 5

    def test_zeek_admin_port_scanning(self):
        events = [
            _make_event(
                event_type="NETWORK_CONN", source_format="zeek",
                source_ip="10.0.0.5", dest_ip=f"10.0.0.{10+i}",
                dest_port=22, offset_seconds=i * 5
            )
            for i in range(6)
        ]
        alerts = lateral_movement.detect(events)
        assert any("Scanning" in a.title or "Internal" in a.title for a in alerts)


# ---------------------------------------------------------------------------
# Privilege escalation
# ---------------------------------------------------------------------------

class TestPrivilegeEscalation:
    def test_sudo_to_root_high_risk(self):
        e = _make_event(
            event_type="SUDO",
            username="bob",
            extra={"target_user": "root", "command": "/bin/bash"},
        )
        alerts = privilege_escalation.detect([e])
        assert len(alerts) == 1
        assert alerts[0].severity == "HIGH"
        assert alerts[0].details["high_risk_command"] is True

    def test_sudo_to_root_low_risk(self):
        e = _make_event(
            event_type="SUDO",
            username="bob",
            extra={"target_user": "root", "command": "/usr/bin/less /var/log/syslog"},
        )
        alerts = privilege_escalation.detect([e])
        assert alerts[0].severity == "MEDIUM"
        assert alerts[0].details["high_risk_command"] is False

    def test_su_to_root(self):
        e = _make_event(event_type="SU", username="alice", extra={"target_user": "root"})
        alerts = privilege_escalation.detect([e])
        assert len(alerts) == 1
        assert alerts[0].severity == "HIGH"

    def test_dangerous_windows_privilege(self):
        e = _make_event(
            event_type="PRIV_ASSIGNED",
            username="admin",
            extra={"privileges": ["SeDebugPrivilege", "SeImpersonatePrivilege"], "event_id": 4672},
        )
        alerts = privilege_escalation.detect([e])
        assert len(alerts) == 1
        assert alerts[0].severity == "HIGH"
        assert "SeDebugPrivilege" in alerts[0].details["dangerous_privileges"]

    def test_safe_windows_privilege_no_alert(self):
        e = _make_event(
            event_type="PRIV_ASSIGNED",
            username="user1",
            extra={"privileges": ["SeChangeNotifyPrivilege"], "event_id": 4672},
        )
        alerts = privilege_escalation.detect([e])
        assert alerts == []

    def test_account_creation(self):
        e = _make_event(event_type="ACCOUNT_CREATED", username="backdoor", extra={"event_id": 4720})
        alerts = privilege_escalation.detect([e])
        assert len(alerts) == 1
        assert alerts[0].alert_type == "PRIVILEGE_ESCALATION"


# ---------------------------------------------------------------------------
# Impossible travel
# ---------------------------------------------------------------------------

class TestImpossibleTravel:
    def test_same_ip_no_alert(self):
        base = datetime(2024, 1, 15, 10, 0, 0)
        events = [
            _make_event(event_type="AUTH_SUCCESS", source_ip="185.220.101.45",
                        username="alice", base_time=base),
            _make_event(event_type="AUTH_SUCCESS", source_ip="185.220.101.45",
                        username="alice", base_time=base, offset_seconds=300),
        ]
        alerts = impossible_travel.detect(events)
        assert alerts == []

    def test_impossible_speed_triggers_alert(self):
        base = datetime(2024, 1, 15, 10, 0, 0)
        # Frankfurt -> Mountain View in 4 minutes — impossible
        events = [
            _make_event(event_type="AUTH_SUCCESS", source_ip="185.220.101.45",
                        username="alice", base_time=base),
            _make_event(event_type="AUTH_SUCCESS", source_ip="8.8.8.8",
                        username="alice", base_time=base, offset_seconds=240),
        ]
        alerts = impossible_travel.detect(events)
        assert len(alerts) == 1
        assert alerts[0].alert_type == "IMPOSSIBLE_TRAVEL"
        assert alerts[0].details["implied_speed_kmh"] > 900

    def test_private_ip_ignored(self):
        base = datetime(2024, 1, 15, 10, 0, 0)
        events = [
            _make_event(event_type="AUTH_SUCCESS", source_ip="192.168.1.1",
                        username="alice", base_time=base),
            _make_event(event_type="AUTH_SUCCESS", source_ip="10.0.0.1",
                        username="alice", base_time=base, offset_seconds=60),
        ]
        alerts = impossible_travel.detect(events)
        assert alerts == []


# ---------------------------------------------------------------------------
# Off-hours login
# ---------------------------------------------------------------------------

class TestOffHours:
    def test_business_hours_no_alert(self):
        # 10:00 on a Tuesday
        e = _make_event(
            event_type="AUTH_SUCCESS",
            base_time=datetime(2024, 1, 16, 10, 0, 0),  # Tuesday
        )
        assert off_hours.detect([e]) == []

    def test_dead_zone_triggers_high(self):
        e = _make_event(
            event_type="AUTH_SUCCESS",
            base_time=datetime(2024, 1, 16, 2, 30, 0),  # Tuesday 02:30
        )
        alerts = off_hours.detect([e])
        assert len(alerts) == 1
        assert alerts[0].details["is_dead_zone"] is True

    def test_weekend_triggers_alert(self):
        e = _make_event(
            event_type="AUTH_SUCCESS",
            base_time=datetime(2024, 1, 20, 14, 0, 0),  # Saturday 14:00
        )
        alerts = off_hours.detect([e])
        assert len(alerts) == 1
        assert alerts[0].details["is_weekend"] is True

    def test_external_ip_escalates_severity(self):
        e = _make_event(
            event_type="AUTH_SUCCESS",
            source_ip="185.220.101.45",  # external
            base_time=datetime(2024, 1, 16, 2, 0, 0),
        )
        alerts = off_hours.detect([e])
        assert alerts[0].details["external_source"] is True
        assert alerts[0].score >= 80


# ---------------------------------------------------------------------------
# Credential stuffing
# ---------------------------------------------------------------------------

class TestCredentialStuffing:
    def _make_stuffing_events(self, ip="91.108.4.1", count=10):
        base = datetime(2024, 1, 15, 11, 0, 0)
        return [
            _make_event(
                source_ip=ip,
                username=f"user{i}",
                offset_seconds=i * 2,
                base_time=base,
            )
            for i in range(count)
        ]

    def test_no_alert_below_threshold(self):
        events = self._make_stuffing_events(count=5)
        assert credential_stuffing.detect(events) == []

    def test_alert_at_threshold(self):
        events = self._make_stuffing_events(count=10)
        alerts = credential_stuffing.detect(events)
        assert len(alerts) == 1
        assert alerts[0].alert_type == "CREDENTIAL_STUFFING"

    def test_spray_classified_correctly(self):
        events = self._make_stuffing_events(count=12)
        alerts = credential_stuffing.detect(events)
        assert alerts[0].details["attack_subtype"] == "Password Spray"

    def test_brute_force_not_flagged_as_stuffing(self):
        # Same username repeated many times — should NOT trigger stuffing
        base = datetime(2024, 1, 15, 11, 0, 0)
        events = [
            _make_event(source_ip="5.5.5.5", username="root",
                        offset_seconds=i * 3, base_time=base)
            for i in range(20)
        ]
        alerts = credential_stuffing.detect(events)
        assert alerts == []


# ---------------------------------------------------------------------------
# Data exfiltration
# ---------------------------------------------------------------------------

class TestDataExfiltration:
    def test_no_alert_small_transfer(self):
        e = _make_event(
            event_type="NETWORK_CONN", source_format="zeek",
            dest_ip="203.0.113.50", dest_port=443,
            extra={"orig_bytes": str(1024 * 1024)},  # 1 MB
        )
        assert data_exfiltration.detect([e]) == []

    def test_alert_large_single_session(self):
        e = _make_event(
            event_type="NETWORK_CONN", source_format="zeek",
            dest_ip="203.0.113.50", dest_port=443,
            extra={"orig_bytes": str(100 * 1024 * 1024)},  # 100 MB
        )
        alerts = data_exfiltration.detect([e])
        assert len(alerts) == 1
        assert alerts[0].alert_type == "DATA_EXFILTRATION"

    def test_cumulative_threshold(self):
        base = datetime(2024, 1, 15, 10, 0, 0)
        events = [
            _make_event(
                event_type="NETWORK_CONN", source_format="zeek",
                dest_ip="203.0.113.50", dest_port=443,
                extra={"orig_bytes": str(60 * 1024 * 1024)},  # 60 MB each
                offset_seconds=i * 60, base_time=base,
            )
            for i in range(3)  # 180 MB total > 150 MB threshold
        ]
        alerts = data_exfiltration.detect(events)
        assert len(alerts) == 1
        assert alerts[0].details["total_transferred_mb"] > 150

    def test_private_destination_ignored(self):
        e = _make_event(
            event_type="NETWORK_CONN", source_format="zeek",
            dest_ip="192.168.1.1", dest_port=443,
            extra={"orig_bytes": str(500 * 1024 * 1024)},
        )
        assert data_exfiltration.detect([e]) == []
