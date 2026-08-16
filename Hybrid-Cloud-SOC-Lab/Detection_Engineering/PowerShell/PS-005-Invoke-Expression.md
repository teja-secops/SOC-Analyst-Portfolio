# PS-005 — PowerShell Invoke-Expression Detection

## Overview
Detects PowerShell process creation where the command line contains `Invoke-Expression`. This behavior can appear in legitimate automation, but it is useful as an investigation signal because dynamically constructed command content may reduce visibility into what is executed.

## Data Source
- Platform: Windows
- Telemetry: Sysmon
- Event ID: 1 — Process Creation
- SIEM: Splunk Enterprise
- Index: `sysmon`

## SPL Query
```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*Invoke-Expression*"
| eval Detection="SOC - PowerShell Invoke-Expression"
| eval Severity="Medium"
| eval MITRE="T1059.001 - PowerShell"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time
```

### Search Optimization
The PowerShell image and `Invoke-Expression` condition are applied directly in the base search to reduce unnecessary post-filtering. Detection name, severity, and MITRE ATT&CK mapping are added to the results for consistent analyst triage across the portfolio.

## Controlled Validation
A harmless PowerShell lab test using the marker `SOC-LAB-PS005-IEX-TEST` was performed to generate Sysmon process-creation telemetry.

Validation flow:

**Controlled PowerShell test → Sysmon Event ID 1 → Splunk ingestion → SPL match → Scheduled alert trigger**

The detection matched successfully in Splunk, and the corresponding alert was confirmed to trigger during controlled lab validation.

## Alert Configuration
- Alert: `SOC - PowerShell Invoke-Expression`
- Type: Scheduled
- Severity: Medium
- Trigger condition: Number of results > 0
- Trigger action: Add to Triggered Alerts
- Validation schedule: Every 5 minutes (`*/5 * * * *`)
- Validation time range: Last 5 minutes

The short schedule is used only during controlled testing. After validation, the alert should be staggered or reduced to avoid unnecessary scheduler contention.

## Investigation Workflow
1. Identify the affected host and user.
2. Review the full PowerShell command line.
3. Review `ParentImage` to identify the launching process.
4. Look for encoded content, download activity, obfuscation, hidden execution, or unusual child processes.
5. Correlate nearby Sysmon events and relevant network telemetry.
6. Determine whether the activity is expected administrative automation or suspicious execution.

## False Positives / Tuning
Legitimate automation and administrative scripts can use `Invoke-Expression`. Treat the detection as a behavioral signal requiring context rather than a confirmed incident by itself.

## MITRE ATT&CK
- Technique: Command and Scripting Interpreter
- Sub-technique: PowerShell
- Technique ID: **T1059.001**

## Validation Status
**Tested and alert trigger confirmed in the SOC home lab.**

## Evidence

### Splunk Detection Result
Screenshot pending GitHub upload.

### Triggered Alert
Screenshot pending GitHub upload.
