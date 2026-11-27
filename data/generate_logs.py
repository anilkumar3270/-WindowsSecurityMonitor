"""
generate_logs.py
Generates synthetic, RFC 1918 compliant authentication logs for BCS703 Mini Project.
Produces exactly 43 records matching the reference baseline distribution:
- 13 Successful Logins
- 26 Failed Logins
- 1 Account Lockout
- 3 Logout Events
- Total: 43 Events
Triggering exactly 8 alerts (2 High, 4 Medium, 2 Low).
"""

import csv
from datetime import datetime, timedelta
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent
SAMPLE_LOG_PATH = DATA_DIR / "sample_auth_logs.csv"
CORRUPT_LOG_PATH = DATA_DIR / "corrupt_sample_logs.csv"

VALID_USERS = {"alice", "bob_finance", "charlie_dev", "david_ops", "eva_hr"}

def generate_baseline_logs():
    base_time = datetime(2026, 10, 30, 8, 30, 0)
    records = []

    # Helper function to append event
    def add_evt(dt, evt_type, user, ip, res, desc):
        records.append({
            "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": evt_type,
            "username": user,
            "source_ip": ip,
            "result": res,
            "description": desc
        })

    # 1. Normal morning baseline logins (5 Successes, 2 Logouts)
    # Alice login & logout
    t = base_time
    add_evt(t, "LOGIN_ATTEMPT", "alice", "192.168.1.15", "SUCCESS", "Standard password authentication")
    t += timedelta(minutes=5)
    add_evt(t, "LOGIN_ATTEMPT", "bob_finance", "192.168.1.22", "SUCCESS", "Standard password authentication")
    t += timedelta(minutes=7)
    add_evt(t, "LOGIN_ATTEMPT", "david_ops", "192.168.1.45", "SUCCESS", "Kerberos ticket granted")
    t += timedelta(minutes=3)
    add_evt(t, "LOGIN_ATTEMPT", "eva_hr", "192.168.1.60", "SUCCESS", "Standard password authentication")
    t += timedelta(minutes=10)
    add_evt(t, "LOGOUT", "david_ops", "192.168.1.45", "SUCCESS", "User session terminated gracefully")
    t += timedelta(minutes=8)
    add_evt(t, "LOGOUT", "eva_hr", "192.168.1.60", "SUCCESS", "User session terminated gracefully")

    # 2. Scenario 1: Alice forgotten password (Rule A alert #1: 5 failures within 5 min)
    # Time: 09:15:00 to 09:18:20
    t = datetime(2026, 10, 30, 9, 15, 0)
    for i in range(5):
        t_fail = t + timedelta(seconds=i * 45)
        add_evt(t_fail, "LOGIN_ATTEMPT", "alice", "192.168.1.15", "FAILURE", "Incorrect password entered")
    # Alice remembers password later (not Rule C because delay > 10 min or count < 3 prior within 10 min of success)
    add_evt(datetime(2026, 10, 30, 9, 45, 0), "LOGIN_ATTEMPT", "alice", "192.168.1.15", "SUCCESS", "Password authenticated after reset")

    # 3. Scenario 2: Bob brute-force leading to Account Lockout (Rule A alert #2: 5 failures, Rule B alert: Lockout)
    # Time: 10:00:00 to 10:03:00
    t = datetime(2026, 10, 30, 10, 0, 0)
    for i in range(5):
        t_fail = t + timedelta(seconds=i * 35)
        add_evt(t_fail, "LOGIN_ATTEMPT", "bob_finance", "192.168.1.22", "FAILURE", "Incorrect credentials")
    
    # Lockout event (High severity Rule B)
    add_evt(t + timedelta(seconds=180), "ACCOUNT_LOCKOUT", "bob_finance", "192.168.1.22", "LOCKOUT", "Account locked due to consecutive authentication failures")

    # 4. Scenario 3: Charlie credential guessing succeeded (Rule C alert: 3 failures followed by SUCCESS within 10 min)
    # Time: 10:30:00 to 10:35:00
    t = datetime(2026, 10, 30, 10, 30, 0)
    for i in range(3):
        t_fail = t + timedelta(seconds=i * 50)
        add_evt(t_fail, "LOGIN_ATTEMPT", "charlie_dev", "192.168.1.105", "FAILURE", "Authentication failed - bad password")
    
    # Charlie Success at 10:33:30 (within 10 minutes of the 3 failures)
    add_evt(datetime(2026, 10, 30, 10, 33, 30), "LOGIN_ATTEMPT", "charlie_dev", "192.168.1.105", "SUCCESS", "Authentication successful via dictionary match")
    add_evt(datetime(2026, 10, 30, 10, 45, 0), "LOGOUT", "charlie_dev", "192.168.1.105", "SUCCESS", "Session ended")

    # 5. Scenario 4: External Subnet IP Probe (192.168.1.200) - Rule D alert #1 (invalid username probe)
    # Attacker probes for non-existent users
    t = datetime(2026, 10, 30, 11, 0, 0)
    add_evt(t, "LOGIN_ATTEMPT", "oracle_svc", "192.168.1.200", "FAILURE", "Unknown user account")
    add_evt(t + timedelta(minutes=2), "LOGIN_ATTEMPT", "ftpuser", "192.168.1.200", "FAILURE", "Unknown user account")

    # 6. Scenario 5: Rapid automated attack & IP spray from 10.0.0.88:
    # 11 rapid attempts within 48 seconds (Time: 11:20:00 to 11:20:48)
    # Triggers:
    # - Rule E (Volume spike: 11 events > 10 in 1 minute from 10.0.0.88)
    # - Rule A (IP Spray: >= 5 failures from 10.0.0.88 within 5 min)
    # - Rule D (Invalid usernames: root, administrator, test_admin)
    t = datetime(2026, 10, 30, 11, 20, 0)
    spray_users = ["root", "administrator", "test_admin", "guest", "backup_user", "sql_admin", "dev_ops", "monitor", "api_user", "service_acc", "temp_user"]
    for i, u in enumerate(spray_users):
        t_spray = t + timedelta(seconds=i * 4)  # 0, 4, 8, ... 40s (within 48s)
        add_evt(t_spray, "LOGIN_ATTEMPT", u, "10.0.0.88", "FAILURE", f"Automated brute-force probe for {u}")

    # 7. Additional routine routine baseline logins to reach exact count:
    # Current counts:
    # Successes: 1(alice)+1(bob)+1(david)+1(eva)+1(alice reset)+1(charlie success) = 6
    # Let's add 7 more routine successes across the day to reach exactly 13 successes
    routine_times = [
        datetime(2026, 10, 30, 12, 0, 0),
        datetime(2026, 10, 30, 13, 10, 0),
        datetime(2026, 10, 30, 14, 15, 0),
        datetime(2026, 10, 30, 15, 0, 0),
        datetime(2026, 10, 30, 15, 45, 0),
        datetime(2026, 10, 30, 16, 20, 0),
        datetime(2026, 10, 30, 17, 0, 0),
    ]
    routine_users = ["alice", "david_ops", "eva_hr", "charlie_dev", "david_ops", "eva_hr", "alice"]
    routine_ips = ["192.168.1.15", "192.168.1.45", "192.168.1.60", "192.168.1.105", "192.168.1.45", "192.168.1.60", "192.168.1.15"]
    for rt, ru, rip in zip(routine_times, routine_users, routine_ips):
        add_evt(rt, "LOGIN_ATTEMPT", ru, rip, "SUCCESS", "Standard authentication success")

    # Let's count totals:
    # Failures:
    # - Alice: 5
    # - Bob: 5
    # - Charlie: 3
    # - 192.168.1.200 (oracle_svc, ftpuser): 2
    # - 10.0.0.88 spray: 11
    # Total Failures = 5 + 5 + 3 + 2 + 11 = 26 failures! Exactly 26!
    # Successes = 6 + 7 = 13! Exactly 13!
    # Lockout = 1! (bob_finance)
    # Logouts = 3! (david_ops, eva_hr, charlie_dev)
    # Total Records = 26 + 13 + 1 + 3 = 43! Exactly 43!

    # Sort all records chronologically
    records.sort(key=lambda x: datetime.strptime(x["timestamp"], "%Y-%m-%d %H:%M:%S"))

    # Write out to sample_auth_logs.csv
    fieldnames = ["timestamp", "event_type", "username", "source_ip", "result", "description"]
    with open(SAMPLE_LOG_PATH, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    print(f"[OK] Generated {len(records)} baseline records at: {SAMPLE_LOG_PATH}")

def generate_corrupt_logs():
    """Generates a dataset containing invalid/corrupt records to verify error handling (TC-04, TC-11, TC-12)."""
    corrupt_records = [
        {"timestamp": "2026-10-30 08:00:00", "event_type": "LOGIN_ATTEMPT", "username": "alice", "source_ip": "192.168.1.10", "result": "SUCCESS", "description": "Valid row"},
        {"timestamp": "INVALID-TIMESTAMP-STR", "event_type": "LOGIN_ATTEMPT", "username": "bob", "source_ip": "192.168.1.11", "result": "FAILURE", "description": "Corrupt timestamp string"},
        {"timestamp": "2026-10-30 08:05:00", "event_type": "LOGIN_ATTEMPT", "username": "", "source_ip": "192.168.1.12", "result": "FAILURE", "description": "Missing username field"},
        {"timestamp": "2026-10-30 08:10:00", "event_type": "", "username": "charlie", "source_ip": "192.168.1.13", "result": "SUCCESS", "description": "Missing event_type"},
        {"timestamp": "2026-10-30 08:15:00", "event_type": "LOGIN_ATTEMPT", "username": "david", "source_ip": "", "result": "SUCCESS", "description": "Missing source IP"},
        {"timestamp": "2026-10-30 08:20:00", "event_type": "LOGIN_ATTEMPT", "username": "eva", "source_ip": "192.168.1.15", "result": "SUCCESS", "description": "Another valid row"}
    ]
    fieldnames = ["timestamp", "event_type", "username", "source_ip", "result", "description"]
    with open(CORRUPT_LOG_PATH, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(corrupt_records)

    print(f"[OK] Generated {len(corrupt_records)} corrupt test records at: {CORRUPT_LOG_PATH}")

if __name__ == "__main__":
    generate_baseline_logs()
    generate_corrupt_logs()
