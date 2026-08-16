# 05 - Sysmon Log Onboarding into Splunk

## Objective

Validate the complete telemetry path from the Windows endpoint to Splunk Enterprise and confirm the fields required by the detection rules are searchable.

## Data Flow

```text
Windows activity
   -> Sysmon
   -> Microsoft-Windows-Sysmon/Operational
   -> Splunk Universal Forwarder
   -> TCP 9997
   -> Splunk Enterprise
   -> index=sysmon
```

## Step 1 - Confirm Local Sysmon Events

On the Windows VM, open Event Viewer:

```text
Applications and Services Logs
  -> Microsoft
  -> Windows
  -> Sysmon
  -> Operational
```

Generate a harmless process event:

```cmd
hostname
```

Confirm a new Event ID 1 is visible locally before troubleshooting Splunk.

## Step 2 - Confirm Forwarder Health

On the Windows VM:

```cmd
sc query SplunkForwarder
```

Then confirm the configured receiver:

```cmd
cd /d "C:\Program Files\SplunkUniversalForwarder\bin"
splunk.exe list forward-server
```

The receiver should be active.

## Step 3 - Confirm Port 9997

```powershell
Test-NetConnection <SPLUNK_SERVER_IP> -Port 9997
```

Expected:

```text
TcpTestSucceeded : True
```

## Step 4 - Search the Sysmon Index

In Splunk:

```spl
index=sysmon
| stats count by host
```

A Windows endpoint host should appear.

## Step 5 - Validate Process Creation

```spl
index=sysmon EventCode=1
| table _time host User Image ParentImage CommandLine
| sort - _time
```

The fields used by the PowerShell detections should be visible, including `Image`, `ParentImage`, and `CommandLine` where present in the event.

## Step 6 - Validate Network Connections

```spl
index=sysmon EventCode=3
| table _time host User Image DestinationIp DestinationPort Protocol
| sort - _time
```

Event ID 3 results depend on the active Sysmon configuration.

## Step 7 - Detection Validation

A simple PowerShell baseline search can verify that endpoint process telemetry is usable for detections:

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| table _time host User ParentImage Image CommandLine
| sort - _time
```

More specific optimized detections are stored under `Detection_Engineering/PowerShell/`.

## Investigation Fields

The current lab commonly uses:

- `_time`
- `host`
- `User`
- `Image`
- `ParentImage`
- `CommandLine`
- `DestinationIp`
- `DestinationPort`
- `Protocol`

## Common Failure Isolation

Use this order when data is missing:

```text
Is the event present in Event Viewer?
        |
        v
Is SplunkForwarder running?
        |
        v
Is the forward server active?
        |
        v
Is TCP 9997 reachable?
        |
        v
Does index=sysmon exist?
        |
        v
Does Splunk receive events from the host?
```

This avoids changing multiple components at the same time and makes troubleshooting easier.

## Validation Checklist

- [ ] Sysmon event visible locally
- [ ] SplunkForwarder service running
- [ ] Forward server active
- [ ] TCP 9997 reachable
- [ ] Windows host visible in `index=sysmon`
- [ ] Event ID 1 searchable
- [ ] Event ID 3 searchable when enabled
- [ ] Detection fields are populated

<img width="1366" height="646" alt="Logs ingections" src="https://github.com/user-attachments/assets/41180783-8dd3-435a-8bfd-dcde6b89a6eb" />
