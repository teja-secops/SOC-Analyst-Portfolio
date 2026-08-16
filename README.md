# 🛡️ SOC Analyst Portfolio

This repository documents hands-on SOC operations, detection engineering, log analysis, alert validation, and security-lab engineering.

## 🌟 Featured Project: Hybrid Cloud SOC & Detection Engineering Lab

The project currently implements a working Windows-to-Splunk telemetry and detection pipeline and is being extended toward a hybrid-cloud controlled attack-simulation environment.

### Current Implemented Stack

- **SIEM:** Splunk Enterprise
- **Telemetry:** Sysmon
- **Endpoint:** Windows 10 virtual machine
- **Log Forwarding:** Splunk Universal Forwarder
- **Transport:** TCP 9997
- **Detection:** Optimized SPL searches with MITRE ATT&CK mapping
- **Alerting:** Splunk scheduled alerts and Triggered Alerts
- **Analysis:** SOC analyst dashboards and investigation searches

### Current Data Flow

```text
Windows 10 VM
   -> Sysmon
   -> Splunk Universal Forwarder
   -> TCP 9997
   -> Splunk Enterprise
   -> Detection Searches
   -> Alerts
   -> SOC Analyst Dashboard
```

### Planned Hybrid-Cloud Extension

```text
Kali Linux (GCP)
   -> Tailscale VPN
   -> Windows 10 VM
   -> Sysmon
   -> Splunk Universal Forwarder
   -> Splunk Enterprise
   -> SOC Dashboard
```

The Kali Linux / GCP / Tailscale attack-simulation layer is listed as a planned phase until deployment and validation are complete.

## 📚 Lab Documentation

- [Hybrid Cloud SOC Lab](./Hybrid-Cloud-SOC-Lab/README.md)
- [Architecture](./Hybrid-Cloud-SOC-Lab/Architecture.md)
- [Setup Documentation](./Hybrid-Cloud-SOC-Lab/Setup/README.md)
- [PowerShell Detection Engineering](./Hybrid-Cloud-SOC-Lab/Detection_Engineering/PowerShell/README.md)

## 🔬 Detection Engineering

The current PowerShell detection set includes validated detections for:

- PowerShell execution baseline
- Encoded commands
- Execution Policy Bypass
- Hidden PowerShell windows
- Invoke-Expression
- Invoke-WebRequest
- WebClient / DownloadString activity

Additional detections for event-log clearing, administrative-group persistence, shadow-copy deletion, and LOLBin network behavior are being validated as the next detection phase.

## 🛠️ Core Competencies Demonstrated

- Security monitoring and log analysis
- Splunk Enterprise administration and SPL
- Sysmon telemetry engineering
- Detection engineering and tuning
- MITRE ATT&CK mapping
- Alert validation and investigation
- Scheduler troubleshooting
- SOC dashboard monitoring
- Incident-response-oriented analysis

## 📂 Repository Structure

```text
SOC-Analyst-Portfolio/
|
├── Hybrid-Cloud-SOC-Lab/
│   ├── README.md
│   ├── Architecture.md
│   ├── Setup/
│   └── Detection_Engineering/
|
├── Incident-Response/
├── Threat-Hunting/
└── Malware-Analysis/
```

## 🎯 Next Project Phases

- Complete the remaining endpoint and LOLBin detections
- Deploy Kali Linux in GCP
- Connect the simulation environment using Tailscale
- Perform controlled attack simulations
- Expand incident-response and threat-hunting case studies
- Add additional dashboard and troubleshooting documentation

> All attack activity documented in this repository is performed only in controlled lab environments for defensive security validation.

⭐ Maintained by Teja as a hands-on SOC and detection-engineering portfolio.
