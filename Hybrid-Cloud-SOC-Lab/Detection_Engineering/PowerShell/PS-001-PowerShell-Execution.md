# PS-001 — PowerShell Execution Baseline Detection

## Overview
Provides baseline visibility into PowerShell process execution captured through Sysmon Event ID 1. PowerShell execution alone is not malicious, so this rule is intended primarily for visibility, investigation context, and detection-development testing rather than continuous high-volume alerting.

## Data Source
- Platform: Windows
- Telemetry: Sysmon
- Event ID: 1 — Process Creation
- SIEM: Splunk Enterprise
- Index: `sysmon`

## SPL Query
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| eval Detection="PowerShell Execution"
| eval Severity="Low"
| eval MITRE="T1059.001 - PowerShell"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time
```

### Search Optimization
The PowerShell image condition is applied directly in the base search to reduce unnecessary post-filtering. Detection name, severity, and MITRE ATT&CK mapping are added to make the output easier to triage and consistent with the other PowerShell detections in this portfolio.

## Controlled Validation
A harmless PowerShell test containing the marker below was executed in the Windows lab endpoint:

`SOC-LAB-PS001-TEST`

Validation flow:

**Controlled PowerShell test → Sysmon Event ID 1 → Splunk ingestion → SPL match**

The test event was successfully identified in Splunk, confirming the endpoint telemetry and detection query were functioning correctly.

## Alert Tuning Decision
A continuous alert for generic PowerShell execution generated excessive noise because PowerShell is commonly used for legitimate activity. The baseline alert was therefore removed/disabled rather than retained as a noisy production-style alert.

This is an intentional tuning decision: higher-confidence behavioral detections such as encoded commands, execution-policy bypass, hidden windows, and suspicious download behavior are better candidates for actionable alerting.

## Investigation Workflow
1. Identify the host and user executing PowerShell.
2. Review the complete command line.
3. Review the parent process and surrounding process-creation events.
4. Look for suspicious flags, encoded content, downloads, hidden execution, or unusual parent-child relationships.
5. Correlate with other endpoint and network telemetry when suspicious behavior is present.

## False Positives / Tuning
Generic PowerShell execution has a high expected legitimate-use rate. This detection should be used as baseline telemetry or hunting context rather than treated as a confirmed security incident by itself.

## MITRE ATT&CK
- Technique: Command and Scripting Interpreter
- Sub-technique: PowerShell
- Technique ID: **T1059.001**

## Validation Status
**Tested and validated in the SOC home lab. Baseline alert intentionally removed due to noise.**

## Evidence
A Splunk search-result screenshot was captured during validation. The screenshot can be embedded here once uploaded to GitHub.
