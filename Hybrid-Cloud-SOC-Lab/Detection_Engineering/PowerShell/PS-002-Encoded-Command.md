# PS-002 — PowerShell Encoded Command Detection

## Overview
Detects PowerShell process creation containing `-EncodedCommand` or the abbreviated `-enc` parameter. Encoded PowerShell is not automatically malicious, but it is a high-value investigation signal because encoding can obscure command content.

## Data Source
- Platform: Windows
- Telemetry: Sysmon
- Event ID: 1 — Process Creation
- SIEM: Splunk Enterprise
- Index: `sysmon`

## SPL Query
```spl
index=sysmon EventCode=1 Image="*powershell.exe" (CommandLine="*-EncodedCommand*" OR CommandLine="*-enc*")
| eval Detection="PowerShell Encoded Command"
| eval Severity="High"
| eval MITRE="T1059.001 - PowerShell"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time
```

### Search Optimization
For better search performance, the PowerShell image and encoded-command conditions are applied directly in the base search instead of retrieving a broader Sysmon Event ID 1 dataset and post-filtering it. Detection name, severity, and MITRE ATT&CK mapping are added to the result set for faster analyst triage.

## Controlled Validation
A harmless encoded PowerShell command was executed in the lab to validate the detection path.

Validation flow:

**Controlled PowerShell test → Sysmon Event ID 1 → Splunk ingestion → SPL match → Alert trigger**

During the documented validation, Splunk returned **5 matching events** for the encoded-command search. The alert `SOC - PowerShell Encoded Command Detected` also fired successfully and was configured with **High** severity at the time of validation.

## Evidence

### Splunk Detection Result
The SPL query successfully identified the encoded PowerShell activity in Sysmon process-creation telemetry.

<img width="1358" height="634" alt="PS-002 Splunk encoded command detection results" src="https://github.com/user-attachments/assets/6fc7c664-a7df-4865-89a2-c234eac6aa65" />

### Triggered Alert
The corresponding high-severity PowerShell Encoded Command alert triggered successfully during validation.

<img width="1361" height="331" alt="PS-002 high severity triggered alert" src="https://github.com/user-attachments/assets/ee5a82ad-8072-428a-9b47-8eacf43eac58" />

## Investigation Workflow
1. Identify the affected host and user.
2. Review the complete PowerShell command line.
3. Extract and decode the Base64 payload in a safe analysis workflow when appropriate.
4. Review `ParentImage` to determine the process responsible for launching PowerShell.
5. Correlate nearby Sysmon process events.
6. Look for download, network, persistence, or defense-evasion behavior.
7. Determine whether the encoded execution is expected administrative activity or suspicious behavior.

## False Positives / Tuning
Possible legitimate sources include administrative automation, software deployment, and security/management tooling. The analyst should validate the decoded content and execution context before escalating.

## MITRE ATT&CK
- Technique: Command and Scripting Interpreter
- Sub-technique: PowerShell
- Technique ID: **T1059.001**

## Validation Status
**Tested and validated in the SOC home lab.**
