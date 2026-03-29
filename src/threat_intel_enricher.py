#!/usr/bin/env python3
"""
threat_intel_enricher.py
------------------------
Enriches a list of suspicious IPs or file hashes using
free threat intelligence APIs:
  - AbuseIPDB  (IP reputation)
  - VirusTotal (IP + hash lookup)

Outputs an enriched IOC report in JSON and terminal summary.

Author: Abdul Aziz Junaid Mohammad
GitHub: https://github.com/aziz5500

Setup:
  pip install requests
  Set your API keys as environment variables:
    export ABUSEIPDB_KEY="your_key_here"
    export VT_KEY="your_virustotal_key_here"

  Free API keys:
    AbuseIPDB  : https://www.abuseipdb.com/register
    VirusTotal : https://www.virustotal.com/gui/join-us
"""

import os
import sys
import json
import time
import hashlib
import requests
from datetime import datetime

# ── API KEYS (from environment variables) ───────────────
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
VT_KEY        = os.environ.get("VT_KEY", "")

# ── DEMO MODE (runs without real API keys) ───────────────
DEMO_MODE = not (ABUSEIPDB_KEY and VT_KEY)
# ────────────────────────────────────────────────────────


def demo_abuseipdb(ip: str) -> dict:
    """Return simulated AbuseIPDB response for demo mode."""
    demo_data = {
        "203.0.113.42":  {"abuseConfidenceScore": 97, "countryCode": "CN", "totalReports": 342, "isp": "Unknown ASN", "usageType": "Data Center/Web Hosting/Transit"},
        "185.220.101.5": {"abuseConfidenceScore": 100, "countryCode": "DE", "totalReports": 891, "isp": "Tor Exit Node", "usageType": "Anonymizer"},
        "198.51.100.77": {"abuseConfidenceScore": 65, "countryCode": "RU", "totalReports": 45, "isp": "Generic ISP", "usageType": "Fixed Line ISP"},
    }
    return demo_data.get(ip, {
        "abuseConfidenceScore": 0,
        "countryCode": "US",
        "totalReports": 0,
        "isp": "Unknown",
        "usageType": "Unknown"
    })


def query_abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB for IP reputation."""
    if DEMO_MODE:
        return demo_abuseipdb(ip)
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        if response.status_code == 200:
            return response.json().get("data", {})
        else:
            return {"error": f"HTTP {response.status_code}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def demo_virustotal_ip(ip: str) -> dict:
    """Return simulated VirusTotal IP response."""
    demo_data = {
        "203.0.113.42":  {"malicious": 12, "suspicious": 3, "harmless": 20, "country": "CN"},
        "185.220.101.5": {"malicious": 45, "suspicious": 8, "harmless": 2,  "country": "DE"},
        "198.51.100.77": {"malicious": 5,  "suspicious": 2, "harmless": 55, "country": "RU"},
    }
    return demo_data.get(ip, {"malicious": 0, "suspicious": 0, "harmless": 80, "country": "US"})


def query_virustotal_ip(ip: str) -> dict:
    """Query VirusTotal for IP reputation."""
    if DEMO_MODE:
        return demo_virustotal_ip(ip)
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_KEY},
            timeout=10
        )
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            country = response.json().get("data", {}).get("attributes", {}).get("country", "Unknown")
            return {**stats, "country": country}
        return {"error": f"HTTP {response.status_code}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def classify_threat(abuse_score: int, vt_malicious: int) -> tuple[str, str]:
    """Classify threat level based on scores."""
    if abuse_score >= 75 or vt_malicious >= 10:
        return "CRITICAL", "🔴"
    elif abuse_score >= 40 or vt_malicious >= 5:
        return "HIGH", "🟠"
    elif abuse_score >= 15 or vt_malicious >= 1:
        return "MEDIUM", "🟡"
    else:
        return "LOW", "🟢"


def enrich_ip(ip: str) -> dict:
    """Enrich a single IP with all available threat intel."""
    print(f"  [*] Querying: {ip}")

    abuse_data = query_abuseipdb(ip)
    time.sleep(0.5)  # Rate limiting courtesy
    vt_data = query_virustotal_ip(ip)

    abuse_score  = abuse_data.get("abuseConfidenceScore", 0)
    vt_malicious = vt_data.get("malicious", 0)
    threat_level, icon = classify_threat(abuse_score, vt_malicious)

    return {
        "ioc_type":          "IPv4",
        "indicator":         ip,
        "threat_level":      threat_level,
        "threat_icon":       icon,
        "abuseipdb": {
            "confidence_score": abuse_score,
            "total_reports":    abuse_data.get("totalReports", 0),
            "country":          abuse_data.get("countryCode", "Unknown"),
            "isp":              abuse_data.get("isp", "Unknown"),
            "usage_type":       abuse_data.get("usageType", "Unknown"),
        },
        "virustotal": {
            "malicious":        vt_malicious,
            "suspicious":       vt_data.get("suspicious", 0),
            "harmless":         vt_data.get("harmless", 0),
            "country":          vt_data.get("country", "Unknown"),
        },
        "mitre_context": "T1071 - Application Layer Protocol / T1090 - Proxy" if abuse_score > 50 else "Monitor",
        "recommendation": (
            "BLOCK IMMEDIATELY — High confidence malicious IP." if threat_level == "CRITICAL"
            else "BLOCK AND INVESTIGATE — Suspicious activity detected." if threat_level == "HIGH"
            else "MONITOR CLOSELY — Low-level suspicious activity." if threat_level == "MEDIUM"
            else "No immediate action required."
        )
    }


def generate_report(enriched: list[dict], output: str = "threat_intel_report.json") -> None:
    """Save enriched IOC report."""
    critical = [e for e in enriched if e["threat_level"] == "CRITICAL"]
    high     = [e for e in enriched if e["threat_level"] == "HIGH"]

    report = {
        "report_title":   "Threat Intelligence Enrichment Report",
        "generated_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "analyst":        "Abdul Aziz Junaid Mohammad",
        "tool":           "threat_intel_enricher.py",
        "demo_mode":      DEMO_MODE,
        "sources":        ["AbuseIPDB", "VirusTotal"],
        "summary": {
            "total_iocs":    len(enriched),
            "critical":      len(critical),
            "high":          len(high),
            "action_required": len(critical) + len(high)
        },
        "iocs": enriched
    }
    with open(output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Report saved: {output}")


def print_summary(enriched: list[dict]) -> None:
    """Print terminal summary."""
    print("\n" + "="*60)
    print("  THREAT INTELLIGENCE ENRICHMENT REPORT")
    if DEMO_MODE:
        print("  [DEMO MODE — simulated data, no real API calls]")
    print("="*60)
    for e in enriched:
        print(f"\n  {e['threat_icon']} {e['indicator']}  [{e['threat_level']}]")
        print(f"     AbuseIPDB Score : {e['abuseipdb']['confidence_score']}%  ({e['abuseipdb']['total_reports']} reports)")
        print(f"     VT Malicious    : {e['virustotal']['malicious']} engines")
        print(f"     Country         : {e['abuseipdb']['country']}")
        print(f"     ISP             : {e['abuseipdb']['isp']}")
        print(f"     Action          : {e['recommendation']}")
    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    # Default IOCs to enrich — replace or extend with your own
    default_iocs = [
        "203.0.113.42",
        "185.220.101.5",
        "198.51.100.77",
    ]

    if len(sys.argv) > 1 and sys.argv[1] != "--demo":
        iocs = sys.argv[1:]
    else:
        iocs = default_iocs

    if DEMO_MODE:
        print("\n[!] Running in DEMO MODE (no API keys set)")
        print("    Set ABUSEIPDB_KEY and VT_KEY env vars for live queries.\n")

    print(f"[*] Enriching {len(iocs)} IOC(s)...\n")
    enriched = [enrich_ip(ip) for ip in iocs]

    print_summary(enriched)
    generate_report(enriched)
