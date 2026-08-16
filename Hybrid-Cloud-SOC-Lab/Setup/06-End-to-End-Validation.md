# 06 - End-to-End Validation

## Objective

Confirm that the SOC lab works as one complete pipeline before adding the Kali Linux / GCP / Tailscale attack-simulation layer.

## Expected Pipeline

```text
Windows test activity
   -> Sysmon captures telemetry
   -> Universal Forwarder reads the event channel
   -> Events are sent to Splunk on TCP 9997
   -> Splunk indexes the event in index=sysmon
   -> Detection SPL matches
   -> Alert is triggered
   -> SOC dashboard / Triggered Alerts shows the result
```

## 1. Endpoint Validation

Generate a harmless command on the Windows VM:

```cmd
hostname
```

Expected:

- Sysmon Event ID 1 appears in the local Sysmon Operational log.

## 2. Forwarder Validation

```cmd
sc query SplunkForwarder
```

Expected:

```text
STATE : RUNNING
```

Check the receiver:

```cmd
cd /d "C:\Program Files\SplunkUniversalForwarder\bin"
splunk.exe list forward-server
```

Expected:

- `<SPLUNK_SERVER_IP>:9997` is active.

## 3. Network Validation

```powershell
Test-NetConnection <SPLUNK_SERVER_IP> -Port 9997
```

Expected:

```text
TcpTestSucceeded : True
```

## 4. Splunk Ingestion Validation

```spl
index=sysmon
| stats count by host
```

Expected:

- The Windows endpoint appears as a source host.

## 5. Sysmon Event Validation

Process creation:

```spl
index=sysmon EventCode=1
| table _time host User Image ParentImage CommandLine
| sort - _time
```

Network connection:

```spl
index=sysmon EventCode=3
| table _time host Image DestinationIp DestinationPort Protocol
| sort - _time
```

## 6. Detection Validation

Run one previously tested detection, for example the PowerShell execution baseline:

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| eval Detection="PowerShell Execution"
| eval Severity="Low"
| eval MITRE="T1059.001 - PowerShell"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time
```

Expected:

- Relevant PowerShell execution appears in the result set.

## 7. Alert Validation

For a behavioral detection configured as a scheduled alert:

- Use a short validation schedule only during testing.
- Confirm `Number of results > 0` triggers the alert.
- Confirm `Add to Triggered Alerts` is enabled.
- Confirm the severity matches the detection documentation.

Expected:

- The fired detection appears in Splunk Triggered Alerts.

## 8. Dashboard Validation

Confirm the SOC dashboard displays the expected detection or alert data.

## 9. Scheduler Health

Because this is a resource-constrained home lab, avoid leaving many detections on aggressive validation schedules. After testing:

- Stagger scheduled searches.
- Increase intervals where appropriate.
- Remove or disable noisy baseline alerts.
- Review Splunk internal scheduler logs when searches are skipped.

## Final Readiness Checklist

- [ ] Windows VM is stable
- [ ] Sysmon service is running
- [ ] Event ID 1 telemetry is available
- [ ] Event ID 3 telemetry is available when configured
- [ ] Splunk Universal Forwarder is running
- [ ] Forward server is active
- [ ] TCP 9997 works
- [ ] `index=sysmon` receives events
- [ ] SPL detections return expected results
- [ ] Behavioral alerts trigger successfully
- [ ] Triggered Alerts receives detections
- [ ] SOC dashboard displays alert data
- [ ] Scheduler is not overloaded by temporary test schedules

Once this checklist passes, the existing telemetry and detection pipeline is ready for the next phase: **Kali Linux in GCP connected through Tailscale for controlled attack simulation.**
