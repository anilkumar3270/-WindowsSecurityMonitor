"""
log_parser.py
Module 2: Resilient Log Ingestion, Schema Validation, and Timestamp Standardization.
Adheres strictly to the BCS703 specification:
- Ingests structured system authentication logs (CSV).
- Validates 6 mandatory fields: timestamp, event_type, username, source_ip, result, description.
- Normalizes varied timestamp formats into native Python datetime objects.
- Isolates malformed or incomplete records into an error registry without crashing.
- Computes comprehensive summary statistics (total events, successes, failures, unique entities).
"""

import csv
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional

MANDATORY_FIELDS = ["timestamp", "event_type", "username", "source_ip", "result", "description"]

TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
]

def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse various timestamp representations into a Python datetime object."""
    if not ts_str or not isinstance(ts_str, str):
        return None
    
    clean_ts = ts_str.strip().replace("Z", "")
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(clean_ts, fmt)
        except ValueError:
            continue
    return None

def parse_auth_logs(file_path: str | Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Ingests CSV log files, validates schema, and parses timestamps.
    Returns:
        (valid_records, parsing_errors)
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found at: {path}")

    valid_records: List[Dict[str, Any]] = []
    parsing_errors: List[Dict[str, Any]] = []

    with open(path, mode="r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        try:
            headers = next(reader, None)
        except StopIteration:
            headers = None

        if not headers:
            # Empty file handled gracefully
            return valid_records, parsing_errors

        headers = [h.strip().lower() for h in headers]

        # Check mandatory headers
        missing_headers = [col for col in MANDATORY_FIELDS if col not in headers]
        if missing_headers:
            parsing_errors.append({
                "row_number": 1,
                "raw_data": str(headers),
                "error_reason": f"Missing mandatory CSV header columns: {', '.join(missing_headers)}"
            })
            return valid_records, parsing_errors

        col_map = {col: headers.index(col) for col in MANDATORY_FIELDS}

        for row_idx, row in enumerate(reader, start=2):
            if not row or all(c.strip() == "" for c in row):
                continue  # skip completely blank lines

            # Verify column count
            if len(row) < len(headers):
                parsing_errors.append({
                    "row_number": row_idx,
                    "raw_data": str(row),
                    "error_reason": f"Incomplete row: expected {len(headers)} columns, found {len(row)}"
                })
                continue

            # Extract fields
            record_raw = {field: row[col_map[field]].strip() for field in MANDATORY_FIELDS}

            # Check for empty mandatory values
            empty_fields = [k for k, v in record_raw.items() if not v]
            if empty_fields:
                parsing_errors.append({
                    "row_number": row_idx,
                    "raw_data": str(row),
                    "error_reason": f"Empty mandatory field(s): {', '.join(empty_fields)}"
                })
                continue

            # Parse and validate timestamp
            parsed_dt = parse_timestamp(record_raw["timestamp"])
            if not parsed_dt:
                parsing_errors.append({
                    "row_number": row_idx,
                    "raw_data": str(row),
                    "error_reason": f"Malformed timestamp string: '{record_raw['timestamp']}'"
                })
                continue

            # Construct valid record
            valid_record = {
                "row_id": row_idx,
                "timestamp": parsed_dt,
                "timestamp_str": parsed_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": record_raw["event_type"].upper(),
                "username": record_raw["username"].lower(),
                "source_ip": record_raw["source_ip"],
                "result": record_raw["result"].upper(),
                "description": record_raw["description"]
            }
            valid_records.append(valid_record)

    # Sort valid records chronologically
    valid_records.sort(key=lambda r: r["timestamp"])
    return valid_records, parsing_errors

def parse_legacy_text_log(file_path: str | Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parses legacy plaintext sample logs (such as sample.log):
    Format: 2026-10-30 09:02:14 WARNING Failed login for user guest
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Legacy log file not found at: {path}")

    valid_records: List[Dict[str, Any]] = []
    parsing_errors: List[Dict[str, Any]] = []

    pattern = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<level>\w+)\s+(?P<message>.+)$"
    )

    with open(path, mode="r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            match = pattern.match(line_str)
            if not match:
                parsing_errors.append({
                    "row_number": idx,
                    "raw_data": line_str,
                    "error_reason": "Unrecognized line syntax"
                })
                continue

            ts = parse_timestamp(match.group("timestamp"))
            level = match.group("level").upper()
            msg = match.group("message")

            # Extract user & result
            result = "SUCCESS" if "successfully" in msg.lower() or "completed" in msg.lower() else "FAILURE"
            event_type = "LOGIN_ATTEMPT"
            if "signed out" in msg.lower():
                event_type = "LOGOUT"
            elif "update" in msg.lower():
                event_type = "SYSTEM_EVENT"

            username = "system"
            if "user" in msg.lower():
                parts = msg.split("user", 1)[-1].strip().split()
                if parts:
                    username = parts[0].strip().lower()

            valid_records.append({
                "row_id": idx,
                "timestamp": ts,
                "timestamp_str": ts.strftime("%Y-%m-%d %H:%M:%S") if ts else match.group("timestamp"),
                "event_type": event_type,
                "username": username,
                "source_ip": "127.0.0.1",
                "result": result,
                "description": msg
            })

    return valid_records, parsing_errors

def calculate_summary_statistics(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates summary KPIs across valid authentication records."""
    if not records:
        return {
            "total_events": 0,
            "successful_logins": 0,
            "failed_logins": 0,
            "account_lockouts": 0,
            "unique_users_count": 0,
            "unique_ips_count": 0,
            "unique_users": [],
            "unique_ips": [],
            "ip_distribution": {},
            "user_distribution": {},
            "status_distribution": {}
        }

    total_events = len(records)
    successful_logins = sum(1 for r in records if r["result"] == "SUCCESS" and r["event_type"] == "LOGIN_ATTEMPT")
    failed_logins = sum(1 for r in records if r["result"] == "FAILURE")
    account_lockouts = sum(1 for r in records if r["event_type"] == "ACCOUNT_LOCKOUT" or r["result"] == "LOCKOUT")

    user_dist: Dict[str, int] = {}
    ip_dist: Dict[str, int] = {}
    status_dist: Dict[str, int] = {}

    for r in records:
        u = r["username"]
        ip = r["source_ip"]
        st = r["result"]

        user_dist[u] = user_dist.get(u, 0) + 1
        ip_dist[ip] = ip_dist.get(ip, 0) + 1
        status_dist[st] = status_dist.get(st, 0) + 1

    return {
        "total_events": total_events,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "account_lockouts": account_lockouts,
        "unique_users_count": len(user_dist),
        "unique_ips_count": len(ip_dist),
        "unique_users": sorted(list(user_dist.keys())),
        "unique_ips": sorted(list(ip_dist.keys())),
        "ip_distribution": ip_dist,
        "user_distribution": user_dist,
        "status_distribution": status_dist
    }
