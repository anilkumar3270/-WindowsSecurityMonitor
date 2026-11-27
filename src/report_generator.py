"""
report_generator.py
Module 5: Security Audit Report Generation and Export.
- Exports alerts and validated events to standardized CSV datasets.
- Compiles comprehensive, human-readable executive audit summaries adhering to NIST SP 800-92 guidelines.
"""

import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from src.detection_engine import SecurityAlert

def generate_text_audit_report(
    summary_stats: Dict[str, Any],
    alerts: List[SecurityAlert],
    log_source_name: str = "sample_auth_logs.csv",
    student_name: str = "K ANIL KUMAR (1AM23CI052)",
    guide_name: str = "Prof. Nagavarshini B R"
) -> str:
    """Generates an executive-level ASCII/Markdown Security Audit Report."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    high_alerts = [a for a in alerts if a.severity == "HIGH"]
    med_alerts = [a for a in alerts if a.severity == "MEDIUM"]
    low_alerts = [a for a in alerts if a.severity == "LOW"]

    lines = [
        "=" * 78,
        "   VISVESVARAYA TECHNOLOGICAL UNIVERSITY - BCS703 MINI PROJECT AUDIT REPORT",
        "           BASIC SECURITY MONITORING SYSTEM USING PYTHON (THEME F)",
        "=" * 78,
        f"Generated At          : {now_str}",
        f"Student Investigator : {student_name}",
        f"Project Guide         : {guide_name}",
        f"Institution           : AMC Engineering College, CSE (AIML), Bengaluru",
        f"Log Source Analyzed   : {log_source_name}",
        "-" * 78,
        "1. EXECUTIVE AUDIT SUMMARY & INGESTION METRICS",
        "-" * 78,
        f"Total Ingested Events : {summary_stats.get('total_events', 0)}",
        f"Successful Logins     : {summary_stats.get('successful_logins', 0)}",
        f"Failed Logins         : {summary_stats.get('failed_logins', 0)}",
        f"Account Lockouts      : {summary_stats.get('account_lockouts', 0)}",
        f"Unique User Accounts  : {summary_stats.get('unique_users_count', 0)}",
        f"Unique Source IPs     : {summary_stats.get('unique_ips_count', 0)}",
        f"Total Security Alerts : {len(alerts)} [HIGH: {len(high_alerts)}, MEDIUM: {len(med_alerts)}, LOW: {len(low_alerts)}]",
        "-" * 78,
        "2. DETECTED THREAT INCIDENTS & BEHAVIORAL CORRELATIONS",
        "-" * 78,
    ]

    if not alerts:
        lines.append("  [INFO] No anomalous patterns or threshold violations detected.")
    else:
        for idx, alert in enumerate(alerts, start=1):
            lines.extend([
                f"Incident #{idx:02d} [{alert.severity}] - {alert.rule_name} ({alert.rule_id})",
                f"  Target Entity : {alert.entity_type} -> {alert.entity_value}",
                f"  Time Window   : {alert.timestamp_start.strftime('%Y-%m-%d %H:%M:%S')} to {alert.timestamp_end.strftime('%H:%M:%S')}",
                f"  Event Count   : {alert.event_count} events involved",
                f"  Details       : {alert.description}",
                f"  Remediation   : {alert.recommendation}",
                ""
            ])

    lines.extend([
        "-" * 78,
        "3. DEFENSE-IN-DEPTH REMEDIATION & HARDENING RECOMMENDATIONS",
        "-" * 78,
        "1. Multi-Factor Authentication (MFA):",
        "   Enforce mandatory FIDO2/TOTP second factors to prevent unauthorized entry",
        "   even when credentials are compromised via brute-force or dictionary attacks.",
        "",
        "2. Progressive Lockout & Exponential Delays (Tarpitting):",
        "   Slow down automated password guessing by applying increasing latency delays",
        "   to responses following consecutive invalid attempts.",
        "",
        "3. Generic Authentication Responses:",
        "   Suppress user enumeration by returning identical error responses",
        "   ('Invalid username or password') for both non-existent users and wrong passwords.",
        "",
        "4. Dynamic Firewall Isolation (SOAR):",
        "   Automatically isolate source IPs exhibiting high-frequency spray (>10/min)",
        "   at the network perimeter via host firewall rules.",
        "=" * 78,
        "                     END OF SECURITY AUDIT REPORT",
        "=" * 78,
    ])

    return "\n".join(lines)

def export_alerts_to_csv(alerts: List[SecurityAlert], output_path: str | Path) -> None:
    """Exports structured alerts to CSV."""
    path = Path(output_path)
    fieldnames = [
        "rule_id", "rule_name", "severity", "entity_type", "entity_value",
        "time_window", "timestamp_start", "timestamp_end", "event_count",
        "description", "recommendation"
    ]
    with open(path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            writer.writerow(alert.to_dict())

def export_events_to_csv(records: List[Dict[str, Any]], output_path: str | Path) -> None:
    """Exports validated records to CSV."""
    path = Path(output_path)
    fieldnames = ["row_id", "timestamp_str", "event_type", "username", "source_ip", "result", "description"]
    with open(path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow({k: r[k] for k in fieldnames})
