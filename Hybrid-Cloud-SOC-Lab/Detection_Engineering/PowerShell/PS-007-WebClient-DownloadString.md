# PS-007 — PowerShell WebClient / DownloadString Detection

## Overview
Detects PowerShell process creation where the command line contains `System.Net.WebClient` or `DownloadString`. These methods are frequently used in legitimate automation, but they are also valuable investigation signals because PowerShell can retrieve remote content and immediately use it in follow-on execution.

## Data Source
- Platform: Windows
- Telemetry: Sysmon
- Event ID: 1 — Process Creation
- SIEM: Splunk Enterprise
- Index: `sysmon`

## SPL Query
```spl
index=sysmon EventCode=1 Image="*powershell.exe" (CommandLine="*System.Net.WebClient*" OR CommandLine="*DownloadString*")
| eval Detection="SOC - PowerShell WebClient Download"
| eval Severity="Medium"
| eval MITRE="T1059.001 - PowerShell"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time
```

### Search Optimization
The PowerShell image and WebClient/DownloadString conditions are applied directly in the base search instead of retrieving a broader Sysmon Event ID 1 dataset and filtering it afterward. Detection name, severity, and MITRE ATT&CK mapping are included in the result set for consistent analyst triage.

## Controlled Validation
A harmless lab command used `System.Net.WebClient` and `DownloadString` against `https://example.com`, together with the marker `SOC-LAB-PS007-WEBCLIENT-TEST`.

Validation flow:

**Controlled PowerShell test → Sysmon Event ID 1 → Splunk ingestion → SPL match → Scheduled alert trigger**

The detection and corresponding alert were successfully tested in the SOC home lab.

## Alert Configuration
- Alert: `SOC - PowerShell WebClient Download`
- Type: Scheduled
- Severity: Medium
- Trigger condition: Number of results > 0
- Trigger action: Add to Triggered Alerts
- Validation schedule: Every 5 minutes (`*/5 * * * *`)
- Validation time range: Last 5 minutes

The short validation schedule is used only during controlled testing. After validation, the alert should be staggered or reduced to avoid unnecessary scheduler contention and repeated matches.

## Investigation Workflow
1. Identify the affected host and user.
2. Review the full PowerShell command line and requested destination.
3. Review `ParentImage` to identify the launching process.
4. Determine whether WebClient or DownloadString use is expected for the user or script.
5. Correlate nearby Sysmon process-creation events and available network telemetry.
6. Check whether retrieved content was written to disk, executed, decoded, or passed into another PowerShell expression.
7. Escalate when the destination, content, parent process, or follow-on behavior is suspicious.

## False Positives / Tuning
Administrative scripts, deployment tooling, update workflows, and automation may legitimately use `System.Net.WebClient` or `DownloadString`. Consider allowlisting known scripts, parent processes, or approved destinations where appropriate.

## MITRE ATT&CK
- Technique: Command and Scripting Interpreter
- Sub-technique: PowerShell
- Technique ID: **T1059.001**

`T1105 - Ingress Tool Transfer` should only be added when the observed behavior clearly represents transfer or retrieval of a file/tool. A generic `DownloadString` request by itself is not enough to claim T1105.

## Validation Status
**Tested and alert trigger confirmed in the SOC home lab.**

## Evidence

### Splunk Detection Result
Screenshot pending GitHub upload.

### Triggered Alert
Screenshot pending GitHub upload.
