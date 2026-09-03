"""
Unit tests for threat intel enrichment.

Run with:  pytest tests/ -v
"""
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.threat_intel import check_ip, enrich_alerts, _is_private
from models import Alert


# ---------------------------------------------------------------------------
# check_ip — local blocklist
# ---------------------------------------------------------------------------

def test_known_tor_exit_node_flagged():
    result = check_ip("185.220.101.45")
    assert result.is_malicious is True
    assert result.confidence >= 90
    assert "Tor Exit Node" in result.categories
    assert result.source == "local_blocklist"


def test_known_scanner_flagged():
    result = check_ip("195.154.0.1")
    assert result.is_malicious is True
    assert result.confidence >= 80


def test_known_c2_flagged():
    result = check_ip("91.108.4.1")
    assert result.is_malicious is True
    assert "C2 Server" in result.categories


def test_clean_ip_not_flagged():
    result = check_ip("1.1.1.1")
    assert result.is_malicious is False


def test_private_ip_not_flagged():
    for ip in ["192.168.1.10", "10.0.0.1", "172.16.0.1", "127.0.0.1"]:
        result = check_ip(ip)
        assert result.is_malicious is False, f"{ip} should not be flagged"


# ---------------------------------------------------------------------------
# _is_private helper
# ---------------------------------------------------------------------------

def test_is_private_rfc1918():
    assert _is_private("10.0.0.1") is True
    assert _is_private("172.16.0.1") is True
    assert _is_private("172.31.255.255") is True
    assert _is_private("192.168.100.1") is True
    assert _is_private("127.0.0.1") is True


def test_is_private_public():
    assert _is_private("8.8.8.8") is False
    assert _is_private("185.220.101.45") is False
    assert _is_private("1.1.1.1") is False


# ---------------------------------------------------------------------------
# enrich_alerts
# ---------------------------------------------------------------------------

def _make_alert(ips):
    return Alert(
        severity="MEDIUM",
        alert_type="BRUTE_FORCE",
        title="Test alert",
        description="Test",
        score=50,
        first_seen=datetime(2024, 1, 1, 10, 0),
        last_seen=datetime(2024, 1, 1, 10, 5),
        involved_ips=ips,
    )


def test_enrich_adds_threat_intel_to_details():
    alert = _make_alert(["185.220.101.45"])
    enrich_alerts([alert])
    assert "threat_intel" in alert.details
    assert len(alert.details["threat_intel"]) == 1
    assert alert.details["threat_intel"][0]["ip"] == "185.220.101.45"


def test_enrich_escalates_severity():
    alert = _make_alert(["185.220.101.45"])  # confidence 100
    enrich_alerts([alert])
    assert alert.severity == "HIGH"  # escalated from MEDIUM


def test_enrich_boosts_score():
    alert = _make_alert(["185.220.101.45"])
    original_score = alert.score
    enrich_alerts([alert])
    assert alert.score > original_score


def test_enrich_no_hit_leaves_alert_unchanged():
    alert = _make_alert(["1.1.1.1"])
    enrich_alerts([alert])
    assert "threat_intel" not in alert.details
    assert alert.severity == "MEDIUM"
    assert alert.score == 50


def test_enrich_skips_private_ips():
    alert = _make_alert(["192.168.1.100", "10.0.0.5"])
    enrich_alerts([alert])
    assert "threat_intel" not in alert.details


def test_enrich_multiple_malicious_ips():
    alert = _make_alert(["185.220.101.45", "185.220.101.46"])
    enrich_alerts([alert])
    assert len(alert.details["threat_intel"]) == 2
    assert alert.score == min(100, 50 + 20)  # capped at +20
