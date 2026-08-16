# PS-003 — PowerShell Execution Policy Bypass Detection

## Overview
Detects PowerShell process creation where the command line contains `-ExecutionPolicy Bypass`. This behavior can be legitimate in administrative automation, but it is also commonly reviewed during investigations because it may allow a PowerShell process to run without normal execution-policy restrictions.

## Data Source
- Platform: Windows
- Telemetry: Sysmon
- Event ID: 1 — Process Creation
- SIEM: Splunk Enterprise
- Index: `sysmon`

## SPL Query
```spl
index=sysmon EventCode=1
| search Image="*powershell.exe"
| search CommandLine="*ExecutionPolicy*Bypass*"
| table _time host User ParentImage Image CommandLine
| sort - _time
```

## Controlled Validation
A harmless lab command was executed with `-ExecutionPolicy Bypass` and a unique test marker:

`SOC-LAB-PS003-BYPASS-TEST`

Validation flow:

**Controlled PowerShell test → Sysmon Event ID 1 → Splunk ingestion → SPL match → Scheduled alert trigger**

During validation, Splunk returned **4 matching events** for the bypass search. The alert `SOC - PowerShell Execution Policy Bypass` then fired successfully as a **Scheduled**, **Medium-severity**, **Per-Result** alert.

## Alert Validation
Observed alert properties during the successful test:

- Alert: `SOC - PowerShell Execution Policy Bypass`
- Type: Scheduled
- Severity: Medium
- Mode: Per Result
- Triggered: 16 Aug 2026 23:50:01 IST

For validation, the schedule was temporarily adjusted so the alert could run within the test window. The normal lab schedule can be reduced afterward to avoid unnecessary scheduler load.

## Investigation Workflow
1. Identify the affected host and user.
2. Review the full PowerShell command line.
3. Confirm whether `ExecutionPolicy Bypass` is expected for the user, script, or administrative workflow.
4. Review `ParentImage` and surrounding Sysmon process-creation events.
5. Check for additional suspicious PowerShell flags such as encoded commands, hidden windows, download activity, or obfuscation.
6. Correlate related endpoint and network telemetry before escalating.

## False Positives / Tuning
Legitimate software deployment, administrator scripts, and management tooling may use execution-policy bypass. The detection should therefore be treated as a suspicious behavior signal rather than a confirmed incident by itself.

## MITRE ATT&CK
- Technique: Command and Scripting Interpreter
- Sub-technique: PowerShell
- Technique ID: **T1059.001**

## Validation Status
**Tested and validated in the SOC home lab.**

Evidence captured during testing includes the Splunk search-result view and the corresponding scheduled triggered-alert view.
