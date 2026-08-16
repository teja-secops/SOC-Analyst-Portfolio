# PS-006 — PowerShell Web Request Detection

## Overview
Detects PowerShell process creation where the command line contains `Invoke-WebRequest`. This behavior is commonly used for legitimate administration and automation, but it is also valuable during investigations because PowerShell can be used to retrieve remote content or interact with external web resources.

## Data Source
- Platform: Windows
- Telemetry: Sysmon
- Event ID: 1 — Process Creation
- SIEM: Splunk Enterprise
- Index: `sysmon`

## SPL Query
```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*Invoke-WebRequest*"
| eval Detection="SOC - PowerShell Web Request"
| eval Severity="Medium"
| eval MITRE="T1059.001 - PowerShell"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time
```

### Search Optimization
The PowerShell image and `Invoke-WebRequest` condition are applied directly in the base search to reduce unnecessary post-filtering. Detection name, severity, and MITRE ATT&CK mapping are added to the result set for consistent analyst triage.

## Controlled Validation
A harmless web request to `https://example.com` was used in the lab to generate PowerShell process-creation telemetry.

Validation flow:

**Controlled PowerShell test → Sysmon Event ID 1 → Splunk ingestion → SPL match → Scheduled alert trigger**

The SPL matched the expected activity and the corresponding alert triggered successfully during controlled lab validation.

## Alert Configuration
- Alert: `SOC - PowerShell Web Request`
- Type: Scheduled
- Severity: Medium
- Trigger condition: Number of results > 0
- Trigger action: Add to Triggered Alerts
- Validation schedule: Every 5 minutes (`*/5 * * * *`)
- Validation time range: Last 5 minutes

The short validation schedule is used only during testing. After validation, the alert should be staggered or reduced to avoid unnecessary scheduler contention and repeated matches.

## Investigation Workflow
1. Identify the affected host and user.
2. Review the complete PowerShell command line and requested URI.
3. Review `ParentImage` to identify the launching process.
4. Determine whether the destination is expected for the user or administrative workflow.
5. Correlate nearby Sysmon process events and available network telemetry.
6. Check for follow-on execution, downloaded content, persistence, or other suspicious PowerShell behavior.
7. Escalate only after validating the execution context and destination.

## False Positives / Tuning
Administrative scripts, software deployment, update workflows, and automation may legitimately use `Invoke-WebRequest`. Consider allowlisting known scripts, destinations, or management processes where appropriate.

## MITRE ATT&CK
- Technique: Command and Scripting Interpreter
- Sub-technique: PowerShell
- Technique ID: **T1059.001**

`T1105 - Ingress Tool Transfer` should only be added when the observed activity actually represents transfer or retrieval of a file/tool, rather than every generic `Invoke-WebRequest` execution.

## Validation Status
**Fully tested and validated in the SOC home lab with both SPL detection evidence and scheduled alert evidence.**

## Evidence

### Splunk Detection Result
The optimized SPL successfully identified the expected `Invoke-WebRequest` activity in Sysmon process-creation telemetry.

<img width="1355" height="650" alt="PS-006 PowerShell Web Request SPL detection results" src="https://github.com/user-attachments/assets/a6756f09-710f-40eb-b4a8-0709add2724f" />

### Triggered Alert
The corresponding medium-severity scheduled alert triggered successfully during validation.

<img width="1366" height="356" alt="PS-006 PowerShell Web Request triggered alert" src="https://github.com/user-attachments/assets/9ea23fc0-eb73-4cd6-bbf8-a6a873d2bc7f" />
