"""
detection_engine.py
Module 3: Security Event Detection Engine.
Implements 5 behavioral detection rules:
- Rule A: Repeated Failed Logins within a 5-minute sliding window (>= 5 failures) [Medium]
- Rule B: Account Lockout Events [High]
- Rule C: Failed Logins Followed by Success within 10 minutes (>= 3 consecutive/prior failures) [High]
- Rule D: Invalid Username Directory Reconnaissance Probes [Low]
- Rule E: Unusual Event Volume Spike (> 10 events within 1 minute from single IP) [Medium]
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

DEFAULT_VALID_USERS = {"alice", "bob_finance", "charlie_dev", "david_ops", "eva_hr"}

class SecurityAlert:
    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        severity: str,
        entity_type: str,
        entity_value: str,
        timestamp_start: datetime,
        timestamp_end: datetime,
        event_count: int,
        description: str,
        recommendation: str,
        raw_events: Optional[List[Dict[str, Any]]] = None
    ):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity.upper()  # HIGH, MEDIUM, LOW
        self.entity_type = entity_type    # USER, IP, SYSTEM
        self.entity_value = entity_value
        self.timestamp_start = timestamp_start
        self.timestamp_end = timestamp_end
        self.event_count = event_count
        self.description = description
        self.recommendation = recommendation
        self.raw_events = raw_events or []

    @property
    def time_window(self) -> str:
        return f"{self.timestamp_start.strftime('%H:%M:%S')} - {self.timestamp_end.strftime('%H:%M:%S')}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "entity_type": self.entity_type,
            "entity_value": self.entity_value,
            "time_window": f"{self.timestamp_start.strftime('%H:%M:%S')} - {self.timestamp_end.strftime('%H:%M:%S')}",
            "timestamp_start": self.timestamp_start.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp_end": self.timestamp_end.strftime("%Y-%m-%d %H:%M:%S"),
            "event_count": self.event_count,
            "description": self.description,
            "recommendation": self.recommendation
        }

class DetectionEngine:
    def __init__(self, valid_users: Optional[set] = None):
        self.valid_users = set(u.lower() for u in (valid_users or DEFAULT_VALID_USERS))

    def evaluate_all_rules(self, records: List[Dict[str, Any]]) -> List[SecurityAlert]:
        """Runs all 5 detection rules across ingested records and returns aggregated alerts."""
        if not records:
            return []

        # Sort chronologically
        sorted_records = sorted(records, key=lambda r: r["timestamp"])

        alerts: List[SecurityAlert] = []
        alerts.extend(self.detect_rule_b_lockouts(sorted_records))
        alerts.extend(self.detect_rule_c_failure_followed_by_success(sorted_records))
        alerts.extend(self.detect_rule_a_repeated_failures(sorted_records))
        alerts.extend(self.detect_rule_e_volume_spikes(sorted_records))
        alerts.extend(self.detect_rule_d_invalid_usernames(sorted_records))

        return alerts

    def detect_rule_a_repeated_failures(
        self, records: List[Dict[str, Any]], window_minutes: int = 5, threshold: int = 5
    ) -> List[SecurityAlert]:
        """
        Rule A: Flags >= 5 failures within a 5-minute sliding window for any single user or source IP.
        Severity: Medium.
        """
        alerts: List[SecurityAlert] = []
        failures = [r for r in records if r["result"] == "FAILURE"]

        # Check by username
        user_failures: Dict[str, List[Dict[str, Any]]] = {}
        for r in failures:
            u = r["username"]
            # Exclude random spray usernames if they only fail once or twice; focus on users with >= threshold
            user_failures.setdefault(u, []).append(r)

        for user, evts in user_failures.items():
            if len(evts) < threshold:
                continue
            # Sliding window check
            triggered = False
            for i in range(len(evts)):
                window_start = evts[i]["timestamp"]
                window_end = window_start + timedelta(minutes=window_minutes)
                window_evts = [e for e in evts[i:] if e["timestamp"] <= window_end]
                if len(window_evts) >= threshold:
                    alerts.append(SecurityAlert(
                        rule_id="RULE-A",
                        rule_name="Repeated Failed Logins (User)",
                        severity="MEDIUM",
                        entity_type="USER",
                        entity_value=user,
                        timestamp_start=window_evts[0]["timestamp"],
                        timestamp_end=window_evts[-1]["timestamp"],
                        event_count=len(window_evts),
                        description=f"User '{user}' recorded {len(window_evts)} failed login attempts within 5 minutes.",
                        recommendation="Enforce progressive login delays (tarpitting) and verify user identity via out-of-band channel.",
                        raw_events=window_evts
                    ))
                    triggered = True
                    break

        # Check by source IP (IP spray)
        ip_failures: Dict[str, List[Dict[str, Any]]] = {}
        for r in failures:
            ip = r["source_ip"]
            ip_failures.setdefault(ip, []).append(r)

        for ip, evts in ip_failures.items():
            if len(evts) < threshold:
                continue
            # Check sliding window
            for i in range(len(evts)):
                window_start = evts[i]["timestamp"]
                window_end = window_start + timedelta(minutes=window_minutes)
                window_evts = [e for e in evts[i:] if e["timestamp"] <= window_end]
                # Trigger IP alert only if multiple users targeted or high spray count
                unique_targeted_users = {e["username"] for e in window_evts}
                if len(window_evts) >= threshold and len(unique_targeted_users) >= 2:
                    alerts.append(SecurityAlert(
                        rule_id="RULE-A",
                        rule_name="Repeated Failed Logins (IP Spray)",
                        severity="MEDIUM",
                        entity_type="IP",
                        entity_value=ip,
                        timestamp_start=window_evts[0]["timestamp"],
                        timestamp_end=window_evts[-1]["timestamp"],
                        event_count=len(window_evts),
                        description=f"Source IP {ip} executed {len(window_evts)} failed logins across {len(unique_targeted_users)} usernames.",
                        recommendation="Deploy temporary dynamic firewall drop rule for source IP and alert network administrator.",
                        raw_events=window_evts
                    ))
                    break

        return alerts

    def detect_rule_b_lockouts(self, records: List[Dict[str, Any]]) -> List[SecurityAlert]:
        """
        Rule B: Detects explicit ACCOUNT_LOCKOUT events.
        Severity: High.
        """
        alerts: List[SecurityAlert] = []
        lockout_events = [
            r for r in records if r["event_type"] == "ACCOUNT_LOCKOUT" or r["result"] == "LOCKOUT"
        ]

        for evt in lockout_events:
            alerts.append(SecurityAlert(
                rule_id="RULE-B",
                rule_name="Account Lockout Event",
                severity="HIGH",
                entity_type="USER",
                entity_value=evt["username"],
                timestamp_start=evt["timestamp"],
                timestamp_end=evt["timestamp"],
                event_count=1,
                description=f"Account '{evt['username']}' locked out due to security policy threshold violation.",
                recommendation="Investigate root cause with user, audit prior authentication events, and ensure MFA is enforced prior to unlocking.",
                raw_events=[evt]
            ))
        return alerts

    def detect_rule_c_failure_followed_by_success(
        self, records: List[Dict[str, Any]], lookback_minutes: int = 10, failure_threshold: int = 3
    ) -> List[SecurityAlert]:
        """
        Rule C: Identifies >= 3 consecutive failures followed by a SUCCESS within 10 minutes for the same user.
        Severity: High (indicator of potential password guessing or credential cracking success).
        """
        alerts: List[SecurityAlert] = []
        user_records: Dict[str, List[Dict[str, Any]]] = {}
        for r in records:
            if r["event_type"] == "LOGIN_ATTEMPT":
                user_records.setdefault(r["username"], []).append(r)

        for user, evts in user_records.items():
            evts_sorted = sorted(evts, key=lambda x: x["timestamp"])
            for idx, evt in enumerate(evts_sorted):
                if evt["result"] == "SUCCESS":
                    s_time = evt["timestamp"]
                    window_start = s_time - timedelta(minutes=lookback_minutes)
                    # Find prior failures within lookback window
                    prior_failures = [
                        e for e in evts_sorted[:idx]
                        if e["result"] == "FAILURE" and window_start <= e["timestamp"] < s_time
                    ]
                    if len(prior_failures) >= failure_threshold:
                        alerts.append(SecurityAlert(
                            rule_id="RULE-C",
                            rule_name="Failed Logins Followed by Success",
                            severity="HIGH",
                            entity_type="USER",
                            entity_value=user,
                            timestamp_start=prior_failures[0]["timestamp"],
                            timestamp_end=s_time,
                            event_count=len(prior_failures) + 1,
                            description=f"User '{user}' had {len(prior_failures)} consecutive failures followed immediately by a SUCCESS. Possible credential guessing or cracked password.",
                            recommendation="Immediate credential revocation/reset, session termination, and mandatory step-up MFA verification.",
                            raw_events=prior_failures + [evt]
                        ))
        return alerts

    def detect_rule_d_invalid_usernames(self, records: List[Dict[str, Any]]) -> List[SecurityAlert]:
        """
        Rule D: Detects login attempts targeting non-existent accounts (Directory Reconnaissance).
        Severity: Low.
        """
        alerts: List[SecurityAlert] = []
        invalid_probes: Dict[str, List[Dict[str, Any]]] = {}

        for r in records:
            if r["username"] not in self.valid_users:
                ip = r["source_ip"]
                invalid_probes.setdefault(ip, []).append(r)

        for ip, evts in invalid_probes.items():
            targeted = sorted(list({e["username"] for e in evts}))
            alerts.append(SecurityAlert(
                rule_id="RULE-D",
                rule_name="Invalid Username Reconnaissance Probe",
                severity="LOW",
                entity_type="IP",
                entity_value=ip,
                timestamp_start=evts[0]["timestamp"],
                timestamp_end=evts[-1]["timestamp"],
                event_count=len(evts),
                description=f"Source IP {ip} attempted {len(evts)} login(s) with non-existent accounts: {', '.join(targeted)}.",
                recommendation="Ensure login endpoints return generic error messages ('Invalid credentials') to suppress account enumeration.",
                raw_events=evts
            ))
        return alerts

    def detect_rule_e_volume_spikes(
        self, records: List[Dict[str, Any]], window_seconds: int = 60, threshold: int = 10
    ) -> List[SecurityAlert]:
        """
        Rule E: Detects > 10 events within 1 minute from a single IP.
        Severity: Medium.
        """
        alerts: List[SecurityAlert] = []
        ip_records: Dict[str, List[Dict[str, Any]]] = {}
        for r in records:
            ip_records.setdefault(r["source_ip"], []).append(r)

        for ip, evts in ip_records.items():
            if len(evts) <= threshold:
                continue
            evts_sorted = sorted(evts, key=lambda x: x["timestamp"])
            for i in range(len(evts_sorted)):
                start_t = evts_sorted[i]["timestamp"]
                end_t = start_t + timedelta(seconds=window_seconds)
                window_evts = [e for e in evts_sorted[i:] if e["timestamp"] <= end_t]
                if len(window_evts) > threshold:
                    alerts.append(SecurityAlert(
                        rule_id="RULE-E",
                        rule_name="Unusual Event Volume Spike",
                        severity="MEDIUM",
                        entity_type="IP",
                        entity_value=ip,
                        timestamp_start=window_evts[0]["timestamp"],
                        timestamp_end=window_evts[-1]["timestamp"],
                        event_count=len(window_evts),
                        description=f"Source IP {ip} generated {len(window_evts)} events within {(window_evts[-1]['timestamp'] - window_evts[0]['timestamp']).seconds} seconds (> {threshold} threshold).",
                        recommendation="Implement network rate limiting / API throttling and trigger temporary IP block.",
                        raw_events=window_evts
                    ))
                    break
        return alerts
