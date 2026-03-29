# 🔐 SOC Log Analysis Scripts

> Python tools for security log analysis, threat detection, and IOC enrichment — built for SOC Analyst workflows.

**Author:** Abdul Aziz Junaid Mohammad  
**LinkedIn:** [linkedin.com/in/azizxjunaid](https://linkedin.com/in/azizxjunaid)  
**Portfolio:** [azizxjunaid-portfolio.netlify.app](https://azizxjunaid-portfolio.netlify.app)

---

## 📁 Scripts

| Script | Purpose | MITRE Coverage |
|--------|---------|---------------|
| `brute_force_detector.py` | Detect brute force attacks from Windows Event Logs | T1110 - Brute Force |
| `firewall_log_analyzer.py` | Analyze firewall logs for port scans, high volume, suspicious ports | T1046 - Network Service Discovery |
| `threat_intel_enricher.py` | Enrich IOCs (IPs) via AbuseIPDB + VirusTotal APIs | T1071, T1090 |

---

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/aziz5500/log-analysis-scripts.git
cd log-analysis-scripts

# Install dependencies
pip install requests

# Run with sample data (no setup needed)
python src/brute_force_detector.py --sample
python src/firewall_log_analyzer.py --sample
python src/threat_intel_enricher.py --demo
```

---

## 🔹 Script 1: Brute Force Detector

Parses Windows Security Event Logs (CSV) and detects brute force login attempts using a sliding time window on **Event ID 4625**.

**How it works:**
- Groups failed logon events by source IP
- Applies sliding window: if ≥ 5 failures from same IP within 3 minutes → ALERT
- Maps findings to **MITRE ATT&CK T1110**
- Outputs JSON incident report

```bash
# Generate sample data and run detection
python src/brute_force_detector.py --sample

# Run on your own log file
python src/brute_force_detector.py /path/to/events.csv
```

**Sample output:**
```
==============================================================
  BRUTE FORCE DETECTION SUMMARY
==============================================================
  [!] 1 ALERT(S) DETECTED

  Alert #1
    Severity    : HIGH
    Source IP   : 192.168.1.105
    Failed Count: 12
    Users       : administrator, admin, svc_account
    Window      : 2026-03-01 14:00:00 → 2026-03-01 14:03:00
    MITRE       : T1110 - Brute Force
    Action      : Block source IP immediately. Reset affected accounts.
==============================================================
```

---

## 🔹 Script 2: Firewall Log Analyzer

Analyzes firewall logs to detect port scanning, high-volume traffic, and connections to known suspicious ports.

**Detects:**
- **Port scanning** — single IP contacting 10+ unique ports
- **High volume** — single IP with 100+ connections
- **Suspicious ports** — connections to ports like 4444 (Metasploit), 445 (SMB), 3389 (RDP), 6667 (IRC/C2)

```bash
python src/firewall_log_analyzer.py --sample
python src/firewall_log_analyzer.py /path/to/firewall.csv
```

---

## 🔹 Script 3: Threat Intel Enricher

Enriches suspicious IPs against **AbuseIPDB** and **VirusTotal** free APIs. Classifies threat level and outputs recommended action.

```bash
# Demo mode (no API keys needed)
python src/threat_intel_enricher.py --demo

# Live mode with API keys
export ABUSEIPDB_KEY="your_key"
export VT_KEY="your_virustotal_key"
python src/threat_intel_enricher.py 203.0.113.42 185.220.101.5

# Free API keys:
# AbuseIPDB  → https://www.abuseipdb.com/register
# VirusTotal → https://www.virustotal.com/gui/join-us
```

**Threat classification:**

| Level | AbuseIPDB Score | VT Malicious Engines |
|-------|----------------|---------------------|
| 🔴 CRITICAL | ≥ 75% | ≥ 10 |
| 🟠 HIGH | ≥ 40% | ≥ 5 |
| 🟡 MEDIUM | ≥ 15% | ≥ 1 |
| 🟢 LOW | < 15% | 0 |

---

## 📊 Output Reports

Each script generates a structured JSON report:

```json
{
  "report_title": "Brute Force Detection Report",
  "generated_at": "2026-03-29 14:32:00",
  "analyst": "Abdul Aziz Junaid Mohammad",
  "total_alerts": 1,
  "alerts": [
    {
      "severity": "HIGH",
      "source_ip": "192.168.1.105",
      "failed_count": 12,
      "mitre_technique": "T1110 - Brute Force",
      "recommendation": "Block source IP immediately..."
    }
  ]
}
```

---

## 🛡️ MITRE ATT&CK Coverage

| Tactic | Technique | Detected By |
|--------|-----------|-------------|
| Credential Access | T1110 - Brute Force | brute_force_detector.py |
| Reconnaissance | T1046 - Network Service Discovery | firewall_log_analyzer.py |
| Command & Control | T1071 - Application Layer Protocol | threat_intel_enricher.py |
| Impact | T1498 - Network DoS | firewall_log_analyzer.py |

---

## 📋 Requirements

```
Python 3.10+
requests
```

---

## 📫 Contact

- **LinkedIn:** [linkedin.com/in/azizxjunaid](https://linkedin.com/in/azizxjunaid)
- **Portfolio:** [azizxjunaid-portfolio.netlify.app](https://azizxjunaid-portfolio.netlify.app)
- **Email:** mohammadarshad60486@gmail.com
