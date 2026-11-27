"""
test_security_monitor.py
Formal Automated Verification Suite for BCS703 Mini Project.
Includes all 14 test cases specified in the reference report (TC-01 to TC-14),
plus full-system integration and legacy compatibility tests (TC-15 and TC-16).
"""

import pytest
from datetime import datetime, timedelta
from pathlib import Path
from src.log_parser import (
    parse_auth_logs,
    parse_legacy_text_log,
    calculate_summary_statistics,
    parse_timestamp
)
from src.detection_engine import DetectionEngine, SecurityAlert
from src.report_generator import generate_text_audit_report
from src.firewall_demo import query_windows_firewall_status, generate_remediation_commands

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SAMPLE_CSV = DATA_DIR / "sample_auth_logs.csv"
CORRUPT_CSV = DATA_DIR / "corrupt_sample_logs.csv"
LEGACY_LOG = Path(__file__).resolve().parent.parent / "sample.log"

# ==========================================
# TEST CASE SUITE (TC-01 TO TC-14 + TC-15,16)
# ==========================================

def test_tc01_baseline_normal_logins():
    """TC-01: Baseline - Normal logins generate 0 false alerts."""
    engine = DetectionEngine()
    t = datetime(2026, 10, 30, 9, 0, 0)
    normal_events = [
        {"timestamp": t + timedelta(minutes=i*10), "event_type": "LOGIN_ATTEMPT", "username": "alice", "source_ip": "192.168.1.10", "result": "SUCCESS", "description": "Normal"}
        for i in range(5)
    ]
    alerts = engine.evaluate_all_rules(normal_events)
    assert len(alerts) == 0, f"Expected 0 alerts, but got {len(alerts)}"

def test_tc02_rule_a_repeated_failures():
    """TC-02: Rule A - 6 failures in 3 min trigger Rule A."""
    engine = DetectionEngine()
    t = datetime(2026, 10, 30, 9, 0, 0)
    failed_events = [
        {"timestamp": t + timedelta(seconds=i*30), "event_type": "LOGIN_ATTEMPT", "username": "alice", "source_ip": "192.168.1.10", "result": "FAILURE", "description": "Failed"}
        for i in range(6)
    ]
    alerts = engine.evaluate_all_rules(failed_events)
    rule_a_alerts = [a for a in alerts if a.rule_id == "RULE-A"]
    assert len(rule_a_alerts) == 1, "Expected exactly 1 Rule A alert"
    assert rule_a_alerts[0].severity == "MEDIUM"
    assert rule_a_alerts[0].entity_value == "alice"

def test_tc03_rule_c_failure_followed_by_success():
    """TC-03: Rule C - 4 failures + 1 success trigger Rule C."""
    engine = DetectionEngine()
    t = datetime(2026, 10, 30, 10, 0, 0)
    events = [
        {"timestamp": t + timedelta(seconds=i*40), "event_type": "LOGIN_ATTEMPT", "username": "charlie_dev", "source_ip": "192.168.1.20", "result": "FAILURE", "description": "Bad password"}
        for i in range(4)
    ]
    # Success within 5 minutes of start (well within 10-minute lookback)
    events.append({
        "timestamp": t + timedelta(minutes=4),
        "event_type": "LOGIN_ATTEMPT",
        "username": "charlie_dev",
        "source_ip": "192.168.1.20",
        "result": "SUCCESS",
        "description": "Correct password"
    })
    alerts = engine.evaluate_all_rules(events)
    rule_c_alerts = [a for a in alerts if a.rule_id == "RULE-C"]
    assert len(rule_c_alerts) == 1, "Expected exactly 1 Rule C alert"
    assert rule_c_alerts[0].severity == "HIGH"
    assert rule_c_alerts[0].entity_value == "charlie_dev"

def test_tc04_resilience_corrupt_isolation(tmp_path):
    """TC-04: Resilience - Corrupt dates/fields isolated safely with zero crashes."""
    test_file = tmp_path / "corrupt_test.csv"
    test_file.write_text(
        "timestamp,event_type,username,source_ip,result,description\n"
        "2026-10-30 09:00:00,LOGIN_ATTEMPT,alice,192.168.1.10,SUCCESS,Valid row\n"
        "MALFORMED-DATE,LOGIN_ATTEMPT,bob,192.168.1.11,FAILURE,Corrupt\n"
        "2026-10-30 09:10:00,LOGIN_ATTEMPT,,192.168.1.12,FAILURE,Missing user\n",
        encoding="utf-8"
    )
    records, errors = parse_auth_logs(test_file)
    assert len(records) == 1, f"Expected 1 valid record, got {len(records)}"
    assert len(errors) == 2, f"Expected 2 isolated errors, got {len(errors)}"

def test_tc05_edge_case_empty_csv(tmp_path):
    """TC-05: Edge Case - Empty CSV handled gracefully with clean return."""
    empty_file = tmp_path / "empty.csv"
    empty_file.write_text("", encoding="utf-8")
    records, errors = parse_auth_logs(empty_file)
    assert records == []
    assert errors == []

def test_tc06a_boundary_four_failures_no_alert():
    """TC-06A: Boundary - 4 failures do NOT trigger Rule A."""
    engine = DetectionEngine()
    t = datetime(2026, 10, 30, 9, 0, 0)
    events = [
        {"timestamp": t + timedelta(seconds=i*30), "event_type": "LOGIN_ATTEMPT", "username": "alice", "source_ip": "192.168.1.10", "result": "FAILURE", "description": "Failed"}
        for i in range(4)
    ]
    alerts = engine.evaluate_all_rules(events)
    rule_a_alerts = [a for a in alerts if a.rule_id == "RULE-A"]
    assert len(rule_a_alerts) == 0, "4 failures should not reach the 5-event threshold"

def test_tc06b_boundary_five_failures_triggers_alert():
    """TC-06B: Boundary - 5 failures MUST trigger Rule A alert."""
    engine = DetectionEngine()
    t = datetime(2026, 10, 30, 9, 0, 0)
    events = [
        {"timestamp": t + timedelta(seconds=i*30), "event_type": "LOGIN_ATTEMPT", "username": "alice", "source_ip": "192.168.1.10", "result": "FAILURE", "description": "Failed"}
        for i in range(5)
    ]
    alerts = engine.evaluate_all_rules(events)
    rule_a_alerts = [a for a in alerts if a.rule_id == "RULE-A"]
    assert len(rule_a_alerts) == 1, "5 failures must trigger Rule A"

def test_tc07_rule_b_lockout_flagged_high():
    """TC-07: Rule B - Lockout event flagged as High severity."""
    engine = DetectionEngine()
    t = datetime(2026, 10, 30, 11, 0, 0)
    events = [{
        "timestamp": t,
        "event_type": "ACCOUNT_LOCKOUT",
        "username": "bob_finance",
        "source_ip": "192.168.1.22",
        "result": "LOCKOUT",
        "description": "Exceeded attempt limit"
    }]
    alerts = engine.evaluate_all_rules(events)
    rule_b = [a for a in alerts if a.rule_id == "RULE-B"]
    assert len(rule_b) == 1
    assert rule_b[0].severity == "HIGH"
    assert rule_b[0].entity_value == "bob_finance"

def test_tc08_rule_d_unknown_username_probe():
    """TC-08: Rule D - Unknown username probe flagged (Low)."""
    engine = DetectionEngine(valid_users={"alice", "bob_finance"})
    t = datetime(2026, 10, 30, 12, 0, 0)
    events = [{
        "timestamp": t,
        "event_type": "LOGIN_ATTEMPT",
        "username": "root_intruder",
        "source_ip": "192.168.1.200",
        "result": "FAILURE",
        "description": "User not found"
    }]
    alerts = engine.evaluate_all_rules(events)
    rule_d = [a for a in alerts if a.rule_id == "RULE-D"]
    assert len(rule_d) == 1
    assert rule_d[0].severity == "LOW"
    assert rule_d[0].entity_value == "192.168.1.200"

def test_tc09_rule_e_volume_spike():
    """TC-09: Rule E - 12 events in 48s trigger volume spike."""
    engine = DetectionEngine()
    t = datetime(2026, 10, 30, 13, 0, 0)
    events = [
        {"timestamp": t + timedelta(seconds=i*4), "event_type": "LOGIN_ATTEMPT", "username": f"user_{i}", "source_ip": "10.0.0.88", "result": "FAILURE", "description": "Rapid burst"}
        for i in range(12)
    ]
    alerts = engine.evaluate_all_rules(events)
    rule_e = [a for a in alerts if a.rule_id == "RULE-E"]
    assert len(rule_e) == 1
    assert rule_e[0].severity == "MEDIUM"
    assert rule_e[0].entity_value == "10.0.0.88"

def test_tc10_ingestion_valid_csv_datetime_objects():
    """TC-10: Ingestion - Valid CSV parses into datetime objects."""
    assert SAMPLE_CSV.exists(), "sample_auth_logs.csv must exist"
    records, errors = parse_auth_logs(SAMPLE_CSV)
    assert len(records) > 0
    assert isinstance(records[0]["timestamp"], datetime)

def test_tc11_validation_malformed_timestamp(tmp_path):
    """TC-11: Validation - Malformed timestamp string detected and error logged."""
    bad_ts_file = tmp_path / "bad_ts.csv"
    bad_ts_file.write_text(
        "timestamp,event_type,username,source_ip,result,description\n"
        "2026-99-99 88:88:88,LOGIN_ATTEMPT,alice,192.168.1.1,SUCCESS,Bad date\n",
        encoding="utf-8"
    )
    records, errors = parse_auth_logs(bad_ts_file)
    assert len(records) == 0
    assert len(errors) == 1
    assert "timestamp" in errors[0]["error_reason"].lower()

def test_tc12_validation_missing_mandatory_field(tmp_path):
    """TC-12: Validation - Missing mandatory field detected and error logged."""
    missing_header_file = tmp_path / "missing_header.csv"
    missing_header_file.write_text(
        "timestamp,username,source_ip,result,description\n"  # missing event_type header
        "2026-10-30 09:00:00,alice,192.168.1.1,SUCCESS,No event_type\n",
        encoding="utf-8"
    )
    records, errors = parse_auth_logs(missing_header_file)
    assert len(records) == 0
    assert len(errors) == 1
    assert "event_type" in errors[0]["error_reason"]

def test_tc13_exception_non_existent_file():
    """TC-13: Exception - Non-existent file path handled gracefully."""
    with pytest.raises(FileNotFoundError):
        parse_auth_logs("non_existent_dummy_file_path.csv")

def test_tc14_stats_empty_input():
    """TC-14: Stats - Summary stats generated for empty input; all counts = 0."""
    stats = calculate_summary_statistics([])
    assert stats["total_events"] == 0
    assert stats["successful_logins"] == 0
    assert stats["failed_logins"] == 0
    assert stats["account_lockouts"] == 0
    assert stats["unique_users_count"] == 0
    assert stats["unique_ips_count"] == 0

def test_tc15_full_baseline_dataset_verification():
    """TC-15: Full baseline verification - Exactly 43 events, 13 successes, 26 failures, 8 alerts."""
    records, errors = parse_auth_logs(SAMPLE_CSV)
    assert len(records) == 43, f"Expected 43 events, got {len(records)}"
    assert len(errors) == 0

    stats = calculate_summary_statistics(records)
    assert stats["successful_logins"] == 13, f"Expected 13 successes, got {stats['successful_logins']}"
    assert stats["failed_logins"] == 26, f"Expected 26 failures, got {stats['failed_logins']}"
    assert stats["account_lockouts"] == 1, f"Expected 1 lockout, got {stats['account_lockouts']}"

    engine = DetectionEngine()
    alerts = engine.evaluate_all_rules(records)
    assert len(alerts) == 8, f"Expected exactly 8 alerts matching reference report, got {len(alerts)}"
    high_count = sum(1 for a in alerts if a.severity == "HIGH")
    med_count = sum(1 for a in alerts if a.severity == "MEDIUM")
    low_count = sum(1 for a in alerts if a.severity == "LOW")
    assert high_count == 2, f"Expected 2 HIGH alerts, got {high_count}"
    assert med_count == 4, f"Expected 4 MEDIUM alerts, got {med_count}"
    assert low_count == 2, f"Expected 2 LOW alerts, got {low_count}"

def test_tc16_legacy_text_log_compatibility():
    """TC-16: Backwards compatibility with original sample.log plain-text file."""
    if LEGACY_LOG.exists():
        records, errors = parse_legacy_text_log(LEGACY_LOG)
        assert len(records) == 7
        stats = calculate_summary_statistics(records)
        assert stats["total_events"] == 7
        # guest had 3 failed logins
        guest_failures = [r for r in records if r["username"] == "guest" and r["result"] == "FAILURE"]
        assert len(guest_failures) == 3
