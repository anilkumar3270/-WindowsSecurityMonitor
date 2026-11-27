"""
monitor.py
Windows Local Security Log Analyzer & Security Monitoring System CLI
BCS703: Cryptography and Network Security Mini Project (Theme F)
Supports both the legacy baseline (sample.log) and the full 5-rule Detection Engine.
"""

import sys
import argparse
from collections import Counter
from pathlib import Path

from src.log_parser import parse_auth_logs, parse_legacy_text_log, calculate_summary_statistics
from src.detection_engine import DetectionEngine
from src.report_generator import generate_text_audit_report

BASE_DIR = Path(__file__).resolve().parent
LEGACY_LOG = BASE_DIR / "sample.log"
CSV_LOG = BASE_DIR / "data" / "sample_auth_logs.csv"
FAILURE_LIMIT = 3

def run_legacy_monitor():
    """Runs the original basic failed-login count check on sample.log."""
    if not LEGACY_LOG.exists():
        print(f"Log file not found: {LEGACY_LOG}")
        return

    lines = LEGACY_LOG.read_text(encoding="utf-8").splitlines()
    failed_users = []

    for line in lines:
        if "failed login for user" in line.lower():
            failed_users.append(line.split("user", 1)[-1].strip())

    counts = Counter(failed_users)

    print("WINDOWS LOCAL SECURITY LOG MONITOR (LEGACY MODE)")
    print(f"Log file: {LEGACY_LOG.name}")
    print(f"Entries reviewed: {len(lines)}")
    print(f"Failed-login events: {len(failed_users)}")
    print("\nMonitoring result:")

    alerts = 0
    for user, count in sorted(counts.items()):
        if count >= FAILURE_LIMIT:
            print(f"ALERT: {user} had {count} failed login attempts.")
            alerts += 1

    if alerts == 0:
        print("No repeated failed-login pattern detected.")

    print("\nReview complete. This tool only reads the supplied sample log.")

def run_full_soc_monitor(log_path: Path):
    """Executes the full 5-rule behavioral detection engine."""
    print("=" * 70)
    print(" WINDOWS DEFENSE-IN-DEPTH SECURITY MONITORING SYSTEM (BCS703)")
    print("=" * 70)

    if not log_path.exists():
        print(f"[!] Error: Log file does not exist at {log_path}")
        return

    if log_path.suffix.lower() == ".csv":
        records, errors = parse_auth_logs(log_path)
    else:
        records, errors = parse_legacy_text_log(log_path)

    stats = calculate_summary_statistics(records)
    engine = DetectionEngine()
    alerts = engine.evaluate_all_rules(records)

    print(f"Target Log File   : {log_path.name}")
    print(f"Total Events      : {stats['total_events']}")
    print(f"Successful Logins : {stats['successful_logins']}")
    print(f"Failed Logins     : {stats['failed_logins']}")
    print(f"Account Lockouts  : {stats['account_lockouts']}")
    print(f"Isolated Errors   : {len(errors)}")
    print(f"Security Alerts   : {len(alerts)}")
    print("-" * 70)

    if alerts:
        print("DETECTED THREAT ALERTS:")
        for idx, alert in enumerate(alerts, start=1):
            print(f" [{alert.severity}] #{idx}: {alert.rule_name} ({alert.rule_id})")
            print(f"   Entity: {alert.entity_type} -> {alert.entity_value}")
            print(f"   Window: {alert.time_window}")
            print(f"   Details: {alert.description}")
            print(f"   Remedy: {alert.recommendation}\n")
    else:
        print("[+] All clear: No policy violations or anomalous bursts detected.")

    print("=" * 70)
    print("To launch the interactive SOC Web Dashboard, run:")
    print("  python -m streamlit run app.py")
    print("=" * 70)

def main():
    parser = argparse.ArgumentParser(description="BCS703 Windows Security Monitor")
    parser.add_argument("--legacy", action="store_true", help="Run in original basic mode on sample.log")
    parser.add_argument("--csv", type=str, default=None, help="Path to CSV authentication log file")
    parser.add_argument("--full", action="store_true", help="Run full 5-rule detection engine on baseline CSV")

    args = parser.parse_args()

    if args.legacy:
        run_legacy_monitor()
    elif args.csv:
        run_full_soc_monitor(Path(args.csv))
    elif args.full or CSV_LOG.exists():
        run_full_soc_monitor(CSV_LOG)
    else:
        run_legacy_monitor()

if __name__ == "__main__":
    main()