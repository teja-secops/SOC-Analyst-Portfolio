# PS-004 — PowerShell Hidden Window Detection

## Overview
Detects PowerShell process execution using the `-WindowStyle Hidden` argument. Hidden PowerShell windows can be used by legitimate automation, but they are also a strong defense-evasion signal because the execution may occur without a visible console window.

## Data Source
- Platform: Windows
- Telemetry: Sysmon
- Event ID: 1 — Process Creation
- SIEM: Splunk Enterprise
- Index: `sysmon`

## SPL Query
```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-WindowStyle Hidden*"
| eval Detection="SOC - PowerShell Hidden Window"
| eval Severity="Medium"
| eval MITRE="T1564.003 - Hidden Window"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time
```

### Search Optimization
The PowerShell image and hidden-window command-line condition are applied directly in the base search to reduce unnecessary post-filtering. Detection name, severity, and MITRE ATT&CK mapping are added to the result set for faster analyst triage.

## Controlled Validation
A harmless lab command is used to generate the expected process-creation telemetry:

```cmd
powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Output 'SOC-LAB-PS004-HIDDEN-TEST'"
```

Validation flow:

**Controlled PowerShell test → Sysmon Event ID 1 → Splunk ingestion → SPL match → Scheduled alert trigger**

## Alert Configuration
- Alert: `SOC - PowerShell Hidden Window`
- Type: Scheduled
- Severity: Medium
- Trigger condition: Number of results > 0
- Trigger action: Add to Triggered Alerts
- Validation schedule: Every 5 minutes (`*/5 * * * *`)
- Validation time range: Last 5 minutes

The short schedule is used only during controlled validation to avoid waiting for an hourly run. After validation, the schedule should be reduced or staggered to limit scheduler contention and duplicate alerting.

## Investigation Workflow
1. Identify the host and user executing PowerShell.
2. Review the full command line for `-WindowStyle Hidden` and any additional suspicious flags.
3. Review `ParentImage` to determine which process launched PowerShell.
4. Correlate nearby Sysmon process-creation events.
5. Look for encoded commands, execution-policy bypass, download activity, persistence, or suspicious child processes.
6. Correlate endpoint and network telemetry before escalation.

## False Positives / Tuning
Legitimate software deployment, login scripts, automation, and management tools may run PowerShell with a hidden window. The analyst should validate the parent process, user context, command content, and surrounding activity before treating the event as malicious.

## MITRE ATT&CK
- Technique: Hide Artifacts
- Sub-technique: Hidden Window
- Technique ID: **T1564.003**

## Validation Status
**SPL and alert configuration documented. Current scheduled-alert evidence will be embedded after trigger confirmation.**

## Evidence

### Splunk Detection Result
Pending current validation screenshot.

### Triggered Alert
Pending current scheduled-trigger screenshot.
