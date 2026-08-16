# 🚨 Detection Engineering: Core SOC Alerts

## 📖 Overview
This document serves as the centralized knowledge base for all custom threat detection rules engineered during the Hybrid Cloud SOC Lab. The objective of this library is to bridge the gap between raw endpoint telemetry and actionable security intelligence. 

Rather than relying on out-of-the-box SIEM alerts, these detections were built from the ground up using **hypothesis-driven threat hunting** and **adversary emulation**. Each rule has been tested, validated, and optimized to ensure high-fidelity alerting with minimal false positives.

## 🔬 Telemetry & Data Sources
The detections in this repository rely heavily on advanced endpoint visibility. The primary data source ingested into Splunk is **Microsoft Sysmon (System Monitor)**, specifically focusing on:
*   **Event ID 1 (Process Creation):** Used to track malicious command-line executions, living-off-the-land binaries (LOLBins), and payload executions.
*   **Event ID 3 (Network Connection):** Used to detect unauthorized outbound communications, C2 beacons, and ingress tool transfers.

## 🎯 Framework Alignment
To ensure a standardized approach to threat detection, every query is strictly mapped to the **MITRE ATT&CK® Framework**. This mapping covers various tactical phases of an attack lifecycle, including:
*   **Execution** (e.g., Malicious PowerShell)
*   **Defense Evasion** (e.g., Log clearing, Hidden windows)
*   **Persistence** (e.g., Local admin escalation)
*   **Impact** (e.g., Ransomware shadow copy deletion)
*   **Command & Control** (e.g., Suspicious outbound traffic)

## 🧩 Anatomy of a Detection Rule
Each detection documented below follows a standardized format to aid Level 1/Level 2 SOC Analysts during triage and incident response:
*   **Description:** The threat context, explaining *what* the adversary is trying to do and *why*.
*   **Severity:** Prioritization tag (Medium, High, Critical) based on the potential impact of the behavior.
*   **MITRE ATT&CK:** The specific Tactic and Technique ID for framework alignment.
*   **SPL Query:** The optimized Splunk Search Processing Language (SPL) code used to trigger the alert, complete with evaluated fields for clean dashboard presentation.

---------------------------------------------------------------------------------------------------------------------

## 💻 1. Execution & Command Control (PowerShell)

### ⚡ 1.1 PowerShell Execution Policy Bypass
**Description:** Detects attempts to launch PowerShell while bypassing execution policy restrictions. Attackers use this to execute malicious scripts on constrained systems.
- **Severity:** 🟡 Medium
- **MITRE ATT&CK:** T1059.001 - PowerShell
```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*ExecutionPolicy Bypass*"
| eval Detection="SOC - PowerShell Execution Policy Bypass"
| eval Severity="Medium"
| eval MITRE="T1059.001 - PowerShell"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time

👻 1.2 PowerShell Hidden Window Execution
Description: Detects PowerShell running with the -WindowStyle Hidden flag. This is a common Defense Evasion technique used to hide terminal windows from the user.

Severity: 🟡 Medium

MITRE ATT&CK: T1564.003 - Hidden Window

index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-WindowStyle Hidden*"
| eval Detection="SOC - PowerShell Hidden Window"
| eval Severity="Medium"
| eval MITRE="T1564.003 - Hidden Window"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time

🌐 1.3 WebClient Download Cradle
Description: Detects the use of Net.WebClient or DownloadString. Adversaries heavily use this to download secondary payloads directly into memory.

Severity: 🔴 High

MITRE ATT&CK: T1105 - Ingress Tool Transfer

index=sysmon EventCode=1 Image="*powershell.exe" (CommandLine="*Net.WebClient*" AND CommandLine="*DownloadString*")
| eval Detection="SOC - PowerShell WebClient Download"
| eval Severity="High"
| eval MITRE="T1105 - Ingress Tool Transfer"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time

🧩 1.4 Obfuscated/Encoded Command Execution
Description: Detects the execution of Base64 encoded PowerShell commands (-enc or -EncodedCommand) used to bypass static string-based detection.

Severity: 🔴 High

MITRE ATT&CK: T1027 - Obfuscated Files or Information

index=sysmon EventCode=1 Image="*powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*")
| eval Detection="SOC - PowerShell Encoded Command Detected"
| eval Severity="High"
| eval MITRE="T1027 - Obfuscated Files"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time

🚀 1.5 PowerShell Invoke-Expression
Description: Detects the use of Invoke-Expression or IEX, which is often used by adversaries to execute strings as code dynamically.

Severity: 🔴 High

MITRE ATT&CK: T1059.001 - PowerShell

index=sysmon EventCode=1 Image="*powershell.exe" (CommandLine="*Invoke-Expression*" OR CommandLine="*IEX*")
| eval Detection="SOC - PowerShell Invoke-Expression"
| eval Severity="High"
| eval MITRE="T1059.001 - PowerShell"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time

📥 1.6 PowerShell Invoke-WebRequest
Description: Detects the use of Invoke-WebRequest or iwr to download malicious files from remote command and control servers.

Severity: 🟡 Medium

MITRE ATT&CK: T1105 - Ingress Tool Transfer

index=sysmon EventCode=1 Image="*powershell.exe" (CommandLine="*Invoke-WebRequest*" OR CommandLine="*iwr*")
| eval Detection="SOC - PowerShell Web Request"
| eval Severity="Medium"
| eval MITRE="T1105 - Ingress Tool Transfer"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time

🛡️ 2. Defense Evasion
🗑️ 2.1 Event Log Clearing
Description: Detects attempts to clear Windows Event Logs using wevtutil to cover tracks and remove forensic evidence.

Severity: 🔴 High

MITRE ATT&CK: T1070.001 - Clear Windows Event Logs

index=sysmon EventCode=1 Image="*wevtutil.exe" CommandLine="* cl *"
| eval Detection="Defense Evasion - Event Log Clearing"
| eval Severity="High"
| eval MITRE="T1070.001 - Clear Windows Event Logs"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time

🔑 3. Persistence & Privilege Escalation
👤 3.1 Adding User to Local Admins
Description: Detects adversaries adding a user account to the local Administrators group using net.exe to maintain high-privileged access.

Severity: 🔴 High

MITRE ATT&CK: T1136.001 - Create Account: Local Account

index=sysmon EventCode=1 Image="*net.exe" CommandLine="*localgroup administrators*/add"
| eval Detection="Persistence - Adding User to Admins"
| eval Severity="High"
| eval MITRE="T1136.001 - Local Account"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time

💥 4. Impact (Ransomware Precursors)
💀 4.1 Shadow Copy Deletion
Description: Detects the deletion of volume shadow copies using vssadmin.exe. This is a critical ransomware behavior meant to prevent system recovery.

Severity: 🚨 Critical

MITRE ATT&CK: T1490 - Inhibit System Recovery

index=sysmon EventCode=1 Image="*vssadmin.exe" CommandLine="*delete shadows*"
| eval Detection="Ransomware Behavior - Shadow Copy Deletion"
| eval Severity="Critical"
| eval MITRE="T1490 - Inhibit System Recovery"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time

🌐 5. Living Off The Land Binaries (LOLBins)
📡 5.1 Suspicious Network Connection (LOLBins)
Description: Detects legitimate Windows binaries (like certutil.exe or mshta.exe) initiating unusual outbound network connections.

Severity: 🔴 High

MITRE ATT&CK: T1105 - Ingress Tool Transfer

index=sysmon EventCode=3 (Image="*certutil.exe" OR Image="*mshta.exe")
| eval Detection="Suspicious Network Connection (LOLBins)"
| eval Severity="High"
| eval MITRE="T1105 - Ingress Tool Transfer"
| table _time host User Image DestinationIp DestinationPort Detection Severity MITRE
| sort - _time

📦 5.2 Certutil File Download
Description: Detects adversaries abusing the legitimate certutil.exe tool to download malicious files directly to the target system.

Severity: 🔴 High

MITRE ATT&CK: T1105 - Ingress Tool Transfer

index=sysmon EventCode=1 Image="*certutil.exe" (CommandLine="*-urlcache*" OR CommandLine="*-split*")
| eval Detection="Certutil File Download"
| eval Severity="High"
| eval MITRE="T1105 - Ingress Tool Transfer"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time

📜 5.3 Suspicious Mshta Execution
Description: Detects the execution of mshta.exe, commonly used by threat actors to bypass application whitelisting and execute malicious HTA payloads.

Severity: 🔴 High

MITRE ATT&CK: T1218.005 - Mshta

index=sysmon EventCode=1 Image="*mshta.exe"
| eval Detection="Suspicious Mshta Execution"
| eval Severity="High"
| eval MITRE="T1218.005 - Mshta"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time
