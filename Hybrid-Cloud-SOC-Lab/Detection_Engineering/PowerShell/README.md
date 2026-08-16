# PowerShell Detection Engineering

This section documents hands-on PowerShell detection engineering performed in a Windows SOC home lab using **Sysmon Event ID 1** and **Splunk Enterprise**.

The workflow used for each rule was:

**Generate test activity → confirm Sysmon telemetry → validate SPL → create alert → verify trigger → tune scheduling/noise**

## Data Source

- Platform: Windows
- Telemetry: Sysmon
- Event ID: 1 — Process Creation
- SIEM: Splunk Enterprise
- Index: `sysmon`

## Detection Catalog

| ID | Detection | Severity | MITRE ATT&CK | Status |
|---|---|---|---|---|
| PS-001 | PowerShell Execution | Low / Baseline | T1059.001 | Tested |
| PS-002 | PowerShell Encoded Command | High | T1059.001 | Tested |
| PS-003 | Execution Policy Bypass | Medium | T1059.001 | Tested |
| PS-004 | Hidden Window | Medium | T1564.003 | Alert evidence pending |
| PS-005 | Invoke-Expression | Medium | T1059.001 | Tested |
| PS-006 | PowerShell Web Request | Medium | T1059.001 / T1105 | Tested |
| PS-007 | WebClient / DownloadString | Medium | T1059.001 / T1105 | Tested |

## Alerting Architecture

The detections were configured as Splunk saved searches/alerts and validated through the fired-alert workflow. During testing, scheduler contention was observed and investigated using Splunk internal scheduler logs.

See [`Scheduler-Troubleshooting.md`](./Scheduler-Troubleshooting.md) for the root-cause investigation.

## Detection Files

- [`01-PowerShell-Execution.spl`](./SPL-Queries/01-PowerShell-Execution.spl)
- [`02-PowerShell-EncodedCommand.spl`](./SPL-Queries/02-PowerShell-EncodedCommand.spl)
- [`03-PowerShell-ExecutionPolicy-Bypass.spl`](./SPL-Queries/03-PowerShell-ExecutionPolicy-Bypass.spl)
- [`04-PowerShell-HiddenWindow.spl`](./SPL-Queries/04-PowerShell-HiddenWindow.spl)
- [`05-PowerShell-InvokeExpression.spl`](./SPL-Queries/05-PowerShell-InvokeExpression.spl)
- [`06-PowerShell-WebRequest.spl`](./SPL-Queries/06-PowerShell-WebRequest.spl)
- [`07-PowerShell-WebClient-Download.spl`](./SPL-Queries/07-PowerShell-WebClient-Download.spl)

## Investigation Fields

The following fields were used during investigation:

- `_time`
- `host`
- `User`
- `Image`
- `ParentImage`
- `CommandLine`

## Notes

PowerShell execution by itself is not automatically malicious. The baseline rule provides visibility, while the behavioral rules identify specific command-line patterns that require additional analyst context and tuning.
