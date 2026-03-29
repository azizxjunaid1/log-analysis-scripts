#!/usr/bin/env python3
"""
firewall_log_analyzer.py
------------------------
Parses firewall logs and identifies suspicious activity:
- Port scanning (many ports from single IP)
- High-volume traffic from single source
- Connections to known suspicious ports
- Blocked traffic analysis

Author: Abdul Aziz Junaid Mohammad
GitHub: https://github.com/aziz5500
"""

import csv
import sys
import json
from collections import defaultdict
from datetime import datetime

# ── CONFIG ──────────────────────────────────────────────
PORT_SCAN_THRESHOLD  = 10   # unique ports from one IP = port scan
HIGH_VOLUME_THRESHOLD = 100  # connections from one IP = high volume

SUSPICIOUS_PORTS = {
    22:    "SSH",
    23:    "Telnet (unencrypted)",
    445:   "SMB (common ransomware vector)",
    3389:  "RDP (brute force target)",
    4444:  "Metasploit default",
    5900:  "VNC",
    6667:  "IRC (C2 channel)",
    8080:  "HTTP Proxy",
    1433:  "MSSQL",
    3306:  "MySQL",
    27017: "MongoDB (often exposed)",
}
# ────────────────────────────────────────────────────────


def parse_firewall_log(filepath: str) -> list[dict]:
    """Parse CSV firewall log."""
    entries = []
    try:
        with open(filepath, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                entries.append(row)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)
    return entries


def normalize_entry(e: dict) -> dict:
    """Normalize field names across different log formats."""
    return {
        "timestamp":  e.get("Timestamp", e.get("Time", e.get("Date/Time", "Unknown"))).strip(),
        "src_ip":     e.get("SourceIP", e.get("Src IP", e.get("Source", "Unknown"))).strip(),
        "dst_ip":     e.get("DestIP", e.get("Dst IP", e.get("Destination", "Unknown"))).strip(),
        "dst_port":   e.get("DestPort", e.get("Dst Port", e.get("Port", "0"))).strip(),
        "protocol":   e.get("Protocol", e.get("Proto", "Unknown")).strip().upper(),
        "action":     e.get("Action", e.get("Disposition", "Unknown")).strip().upper(),
        "bytes":      e.get("Bytes", e.get("BytesSent", "0")).strip(),
    }


def analyze(entries: list[dict]) -> dict:
    """Run all detection checks."""
    normalized = [normalize_entry(e) for e in entries]

    # Aggregate by source IP
    ip_ports     = defaultdict(set)
    ip_count     = defaultdict(int)
    ip_blocked   = defaultdict(int)
    ip_protocols = defaultdict(set)
    susp_conns   = []

    for e in normalized:
        src = e["src_ip"]
        try:
            port = int(e["dst_port"])
        except ValueError:
            port = 0

        ip_ports[src].add(port)
        ip_count[src] += 1
        ip_protocols[src].add(e["protocol"])

        if "DENY" in e["action"] or "BLOCK" in e["action"] or "DROP" in e["action"]:
            ip_blocked[src] += 1

        # Flag connections to suspicious ports
        if port in SUSPICIOUS_PORTS:
            susp_conns.append({
                "timestamp":   e["timestamp"],
                "src_ip":      src,
                "dst_ip":      e["dst_ip"],
                "port":        port,
                "service":     SUSPICIOUS_PORTS[port],
                "protocol":    e["protocol"],
                "action":      e["action"],
                "mitre_note":  "Possible reconnaissance or exploitation attempt"
            })

    # Build findings
    findings = {
        "port_scans":        [],
        "high_volume":       [],
        "suspicious_ports":  susp_conns,
        "top_blocked_ips":   [],
    }

    # Port scan detection
    for ip, ports in ip_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            findings["port_scans"].append({
                "severity":        "HIGH",
                "src_ip":          ip,
                "unique_ports":    len(ports),
                "ports_contacted": sorted(list(ports))[:20],
                "protocols":       list(ip_protocols[ip]),
                "mitre_tactic":    "Reconnaissance",
                "mitre_technique": "T1046 - Network Service Discovery",
                "recommendation":  "Block source IP. Investigate whether internal host is compromised."
            })

    # High volume detection
    for ip, count in ip_count.items():
        if count >= HIGH_VOLUME_THRESHOLD:
            findings["high_volume"].append({
                "severity":       "MEDIUM",
                "src_ip":         ip,
                "total_connections": count,
                "blocked_count":  ip_blocked[ip],
                "mitre_tactic":   "Impact",
                "mitre_technique":"T1498 - Network Denial of Service",
                "recommendation": "Rate-limit or block source IP. Investigate traffic patterns."
            })

    # Top blocked IPs
    blocked_sorted = sorted(ip_blocked.items(), key=lambda x: x[1], reverse=True)[:10]
    findings["top_blocked_ips"] = [
        {"ip": ip, "blocked_count": count} for ip, count in blocked_sorted
    ]

    return findings


def print_summary(findings: dict, total: int) -> None:
    """Print terminal summary."""
    print("\n" + "="*60)
    print("  FIREWALL LOG ANALYSIS SUMMARY")
    print("="*60)
    print(f"  Total log entries analyzed : {total}")
    print(f"  Port scan alerts           : {len(findings['port_scans'])}")
    print(f"  High volume alerts         : {len(findings['high_volume'])}")
    print(f"  Suspicious port connections: {len(findings['suspicious_ports'])}")
    print()

    if findings["port_scans"]:
        print("  [!] PORT SCAN DETECTIONS:")
        for a in findings["port_scans"]:
            print(f"      IP: {a['src_ip']} | {a['unique_ports']} unique ports")
            print(f"      MITRE: {a['mitre_technique']}")
            print(f"      Action: {a['recommendation']}")
            print()

    if findings["suspicious_ports"]:
        print("  [!] SUSPICIOUS PORT CONNECTIONS (sample):")
        for c in findings["suspicious_ports"][:5]:
            print(f"      {c['src_ip']} → port {c['port']} ({c['service']}) [{c['action']}]")
        print()

    if findings["top_blocked_ips"]:
        print("  [i] TOP BLOCKED SOURCE IPs:")
        for b in findings["top_blocked_ips"][:5]:
            print(f"      {b['ip']} — {b['blocked_count']} blocked connections")
    print("="*60 + "\n")


def save_report(findings: dict, total: int, output: str = "firewall_analysis_report.json") -> None:
    """Save full report to JSON."""
    report = {
        "report_title":  "Firewall Log Analysis Report",
        "generated_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "analyst":       "Abdul Aziz Junaid Mohammad",
        "tool":          "firewall_log_analyzer.py",
        "total_entries": total,
        "findings":      findings
    }
    with open(output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report saved to: {output}")


def generate_sample_log(filepath: str = "sample_firewall.csv") -> None:
    """Generate sample firewall log with embedded attack patterns."""
    import random

    rows = [["Timestamp", "SourceIP", "DestIP", "DestPort", "Protocol", "Action", "Bytes"]]
    base = datetime(2026, 3, 1, 9, 0, 0)

    normal_ips = ["10.0.0.5", "10.0.0.12", "10.0.1.8", "172.16.0.20"]

    # Normal traffic
    normal_ports = [80, 443, 53, 8443, 25, 587]
    for i in range(80):
        t = base.replace(second=i * 30)
        rows.append([
            t.strftime("%Y-%m-%d %H:%M:%S"),
            random.choice(normal_ips),
            f"192.168.1.{random.randint(1,50)}",
            random.choice(normal_ports),
            random.choice(["TCP", "UDP"]),
            "ALLOW",
            random.randint(200, 5000)
        ])

    # Port scanner
    scanner_ip = "203.0.113.42"
    scan_ports = list(range(20, 30)) + [80, 443, 445, 3389, 8080, 22, 23, 3306]
    for port in scan_ports:
        t = base.replace(minute=5, second=port)
        rows.append([t.strftime("%Y-%m-%d %H:%M:%S"), scanner_ip,
                     "10.0.0.1", port, "TCP", "DENY", 64])

    # Suspicious port connections
    for port in [4444, 6667, 3389, 445]:
        rows.append([
            base.replace(hour=11).strftime("%Y-%m-%d %H:%M:%S"),
            "198.51.100.77", "10.0.0.5", port, "TCP", "DENY", 128
        ])

    # High volume IP
    flood_ip = "185.220.101.5"
    for i in range(120):
        rows.append([
            base.replace(hour=14, second=i % 60).strftime("%Y-%m-%d %H:%M:%S"),
            flood_ip, "10.0.0.1", 80, "TCP",
            "DENY" if i % 3 == 0 else "ALLOW", random.randint(64, 1500)
        ])

    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

    print(f"[+] Sample firewall log created: {filepath}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python firewall_log_analyzer.py <logfile.csv>")
        print("  python firewall_log_analyzer.py --sample\n")
        sys.exit(0)

    if sys.argv[1] == "--sample":
        generate_sample_log()
        log_file = "sample_firewall.csv"
    else:
        log_file = sys.argv[1]

    print(f"\n[*] Loading firewall log: {log_file}")
    entries = parse_firewall_log(log_file)
    print(f"[*] Entries loaded: {len(entries)}")

    print("[*] Running analysis...")
    findings = analyze(entries)

    print_summary(findings, len(entries))
    save_report(findings, len(entries))
