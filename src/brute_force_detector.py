#!/usr/bin/env python3
"""
brute_force_detector.py
-----------------------
Parses Windows Security Event Logs (CSV format) and detects
brute force login attempts based on Event ID 4625 thresholds.

Author: Abdul Aziz Junaid Mohammad
GitHub: https://github.com/aziz5500
"""

import csv
import sys
import json
from collections import defaultdict
from datetime import datetime, timedelta

# ── CONFIG ──────────────────────────────────────────────
THRESHOLD       = 5      # failed logins to trigger alert
WINDOW_MINUTES  = 3      # time window in minutes
EVENT_ID        = "4625" # Windows failed logon event
# ────────────────────────────────────────────────────────


def parse_log_file(filepath: str) -> list[dict]:
    """Read CSV event log and return list of event dicts."""
    events = []
    try:
        with open(filepath, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                events.append(row)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Could not read file: {e}")
        sys.exit(1)
    return events


def parse_timestamp(ts_str: str) -> datetime | None:
    """Try multiple timestamp formats."""
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts_str.strip(), fmt)
        except ValueError:
            continue
    return None


def detect_brute_force(events: list[dict]) -> list[dict]:
    """
    Sliding window brute force detection.
    Groups Event ID 4625 by source IP, checks if THRESHOLD
    failures occur within WINDOW_MINUTES.
    """
    # Filter to failed logon events only
    failed = []
    for e in events:
        eid = e.get("EventID", e.get("Event ID", "")).strip()
        if eid == EVENT_ID:
            ts = parse_timestamp(
                e.get("TimeCreated", e.get("Time", e.get("Timestamp", "")))
            )
            ip = e.get("IpAddress", e.get("Source IP", e.get("SourceIP", "Unknown"))).strip()
            user = e.get("TargetUserName", e.get("Username", e.get("User", "Unknown"))).strip()
            if ts:
                failed.append({"timestamp": ts, "ip": ip, "user": user})

    if not failed:
        print("[INFO] No Event ID 4625 entries found in log.")
        return []

    # Group by source IP
    by_ip = defaultdict(list)
    for entry in failed:
        by_ip[entry["ip"]].append(entry)

    alerts = []
    window = timedelta(minutes=WINDOW_MINUTES)

    for ip, entries in by_ip.items():
        entries.sort(key=lambda x: x["timestamp"])
        for i, entry in enumerate(entries):
            window_events = [
                e for e in entries
                if entry["timestamp"] <= e["timestamp"] <= entry["timestamp"] + window
            ]
            if len(window_events) >= THRESHOLD:
                # Avoid duplicate alerts for same window
                alert_key = f"{ip}_{entry['timestamp']}"
                if not any(a.get("_key") == alert_key for a in alerts):
                    targeted_users = list(set(e["user"] for e in window_events))
                    alerts.append({
                        "_key": alert_key,
                        "severity":       "HIGH",
                        "alert_type":     "Brute Force Detected",
                        "source_ip":      ip,
                        "targeted_users": targeted_users,
                        "failed_count":   len(window_events),
                        "window_start":   entry["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                        "window_end":     (entry["timestamp"] + window).strftime("%Y-%m-%d %H:%M:%S"),
                        "mitre_tactic":   "Credential Access",
                        "mitre_technique":"T1110 - Brute Force",
                        "recommendation": "Block source IP immediately. Reset affected accounts. Review authentication logs."
                    })

    return alerts


def generate_report(alerts: list[dict], output_file: str = "brute_force_report.json") -> None:
    """Write alerts to JSON report file."""
    clean_alerts = [{k: v for k, v in a.items() if k != "_key"} for a in alerts]
    report = {
        "report_title":   "Brute Force Detection Report",
        "generated_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "analyst":        "Abdul Aziz Junaid Mohammad",
        "tool":           "brute_force_detector.py",
        "threshold":      f"{THRESHOLD} failures in {WINDOW_MINUTES} minutes",
        "mitre_mapping":  "T1110 - Brute Force (Credential Access)",
        "total_alerts":   len(clean_alerts),
        "alerts":         clean_alerts
    }
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report saved to: {output_file}")


def print_summary(alerts: list[dict]) -> None:
    """Print human-readable summary to terminal."""
    print("\n" + "="*60)
    print("  BRUTE FORCE DETECTION SUMMARY")
    print("="*60)
    if not alerts:
        print("  [✓] No brute force activity detected.")
    else:
        print(f"  [!] {len(alerts)} ALERT(S) DETECTED\n")
        for i, a in enumerate(alerts, 1):
            print(f"  Alert #{i}")
            print(f"    Severity    : {a['severity']}")
            print(f"    Source IP   : {a['source_ip']}")
            print(f"    Failed Count: {a['failed_count']}")
            print(f"    Users       : {', '.join(a['targeted_users'])}")
            print(f"    Window      : {a['window_start']} → {a['window_end']}")
            print(f"    MITRE       : {a['mitre_technique']}")
            print(f"    Action      : {a['recommendation']}")
            print()
    print("="*60 + "\n")


def generate_sample_csv(filepath: str = "sample_events.csv") -> None:
    """
    Generate a sample CSV log file for testing.
    Simulates a brute force attack from 192.168.1.105
    """
    import random
    rows = [
        ["TimeCreated", "EventID", "IpAddress", "TargetUserName", "Description"],
    ]
    base_time = datetime(2026, 3, 1, 14, 0, 0)

    # Normal failed logins (spread out)
    normal_ips = ["10.0.0.12", "10.0.0.45", "172.16.0.8"]
    for i in range(10):
        t = base_time + timedelta(minutes=random.randint(0, 120))
        rows.append([
            t.strftime("%Y-%m-%d %H:%M:%S"),
            "4625",
            random.choice(normal_ips),
            f"user{random.randint(1,5)}",
            "An account failed to log on."
        ])

    # Brute force burst from attacker IP
    attacker_ip = "192.168.1.105"
    for i in range(15):
        t = base_time + timedelta(seconds=i * 12)  # 1 attempt every 12 seconds
        rows.append([
            t.strftime("%Y-%m-%d %H:%M:%S"),
            "4625",
            attacker_ip,
            random.choice(["administrator", "admin", "svc_account"]),
            "An account failed to log on."
        ])

    # Mix in some successful logins (different event ID)
    for i in range(5):
        t = base_time + timedelta(minutes=random.randint(0, 60))
        rows.append([
            t.strftime("%Y-%m-%d %H:%M:%S"),
            "4624",
            random.choice(normal_ips),
            f"user{random.randint(1,5)}",
            "An account was successfully logged on."
        ])

    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

    print(f"[+] Sample log file created: {filepath}")
    print(f"    Contains brute force simulation from {attacker_ip}")


# ── MAIN ────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python brute_force_detector.py <logfile.csv>")
        print("  python brute_force_detector.py --sample   (generate test data + run)\n")
        sys.exit(0)

    if sys.argv[1] == "--sample":
        sample_file = "sample_events.csv"
        generate_sample_csv(sample_file)
        log_file = sample_file
    else:
        log_file = sys.argv[1]

    print(f"\n[*] Parsing log file: {log_file}")
    events = parse_log_file(log_file)
    print(f"[*] Total events loaded: {len(events)}")

    print(f"[*] Running brute force detection (threshold: {THRESHOLD} in {WINDOW_MINUTES} min)...")
    alerts = detect_brute_force(events)

    print_summary(alerts)
    generate_report(alerts)
