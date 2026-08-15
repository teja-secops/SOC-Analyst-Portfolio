# 🛡️ SOC Analyst Portfolio

Welcome to my Cybersecurity Portfolio. This repository documents my journey as a SOC Analyst and contains hands-on projects, attack simulations, and detection engineering labs.

## 🌟 Featured Project: Hybrid Cloud SOC & Detection Engineering Lab

**Objective:** Designed and built a comprehensive Hybrid Cloud Security Operations Center (SOC) environment to ingest telemetry, execute advanced adversary emulations, and develop high-fidelity detection rules.

**🛠️ Tech Stack & Tools:**
- **SIEM:** Splunk Enterprise
- **Telemetry:** Sysmon (Process Creation, Network Connections)
- **Target Environment:** Windows 10 Virtual Machine
- **Attack Infrastructure:** Kali Linux (GCP) & Atomic Red Team (ART)
- **Networking:** Tailscale VPN

**🚀 Key Achievements:**
- Optimized Splunk architecture and Universal Forwarder configs to achieve near real-time ingestion, eliminating system latency.
- Developed and validated optimized SPL rules mapped to the MITRE ATT&CK framework for critical threats:
  - **T1490:** Ransomware Shadow Copy Deletion
  - **T1070:** Defense Evasion (Event Log Clearing)
  - **T1136:** Persistence (Local Admin Escalation)
  - **T1059 / T1105:** PowerShell LOLBins & C2 Connections

---

## 🛠️ Core Competencies & Areas of Focus
- 🔍 Threat Hunting
- 📊 Splunk Enterprise & Log Analysis
- 🚨 Incident Response
- 🎯 Detection Engineering & Alert Optimization
- 🗺️ MITRE ATT&CK Mapping

## 📂 Repository Structure
```text
SOC-Analyst-Portfolio
│
├── 📁 Hybrid-Cloud-SOC-Lab       # (Current Active Project Files)
│   ├── Detection_Engineering     # Optimized SPL queries & MITRE mappings
│   ├── Dashboards                # XML source code for Splunk dashboards
│   └── Architecture              # Network and data flow diagrams
│
├── 📁 Incident-Response
├── 📁 Threat-Hunting
└── 📁 Malware-Analysis

🎯 Future Goals
Perform advanced adversary emulation using Kali Linux via GCP.

Implement automated Incident Response playbooks.

Expand detections with Sigma Rules and open-source tooling.

⭐ Created and maintained by Teja — Aspiring SOC Analyst / Security Engineer. This repository will be updated regularly as I complete new cybersecurity phases.
