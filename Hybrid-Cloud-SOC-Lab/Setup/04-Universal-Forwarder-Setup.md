# 04 - Splunk Universal Forwarder Setup

## Objective

Install and configure Splunk Universal Forwarder on the Windows endpoint so Sysmon telemetry is forwarded to Splunk Enterprise.

## Architecture

```text
Windows 10 VM
   |
   | Sysmon Operational log
   v
Splunk Universal Forwarder
   |
   | TCP 9997
   v
Splunk Enterprise
```

## Installation

Install Splunk Universal Forwarder on the Windows VM using the official Windows installer.

For this lab, the forwarder service should run using a local service context with permission to read the required Windows event channels. The lab was stabilized by running the Splunk Forwarder service under **Local System**.

Default installation path:

```text
C:\Program Files\SplunkUniversalForwarder
```

## Configure the Forward Server

Open an elevated Command Prompt:

```cmd
cd /d "C:\Program Files\SplunkUniversalForwarder\bin"
```

Add the Splunk Enterprise receiver:

```cmd
splunk.exe add forward-server <SPLUNK_SERVER_IP>:9997
```

If authentication is requested, use the local Universal Forwarder administrative credentials. Do not place real credentials in public documentation.

List configured forward servers:

```cmd
splunk.exe list forward-server
```

Expected state should show the Splunk receiver as active once connectivity is working.

## Configure Sysmon Event Collection

Create or edit:

```text
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

Example configuration:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = 1
index = sysmon
```

This tells the Universal Forwarder to monitor the Sysmon Operational event channel and send the events to the `sysmon` index.

## Restart the Forwarder

After configuration changes:

```cmd
cd /d "C:\Program Files\SplunkUniversalForwarder\bin"
splunk.exe restart
```

## Service Verification

Check the Windows service:

```cmd
sc query SplunkForwarder
```

Expected state:

```text
STATE : RUNNING
```

## Network Verification

From the Windows VM:

```powershell
Test-NetConnection <SPLUNK_SERVER_IP> -Port 9997
```

Expected result:

```text
TcpTestSucceeded : True
```

## Troubleshooting Used in This Lab

### Forwarder is running but no data arrives

Check:

1. Splunk Enterprise is listening on 9997.
2. The endpoint can reach `<SPLUNK_SERVER_IP>:9997`.
3. The `sysmon` index exists.
4. `inputs.conf` points to the correct Sysmon channel.
5. The forwarder service has permission to read the event log.
6. Restart the forwarder after configuration changes.

### VM IP keeps changing

A Host-Only network adapter can provide a stable local path between the Windows VM and the Splunk Enterprise host.

### Service permission problems

The lab forwarder was run under the Local System account so it could reliably read the required Windows event channels.

## Validation Checklist

- [ ] Universal Forwarder installed
- [ ] SplunkForwarder service running
- [ ] Splunk receiver configured on port 9997
- [ ] Receiver appears active
- [ ] Sysmon Operational log configured in `inputs.conf`
- [ ] TCP 9997 connectivity succeeds
- [ ] Events begin appearing in `index=sysmon`

## Security Note
<img width="1366" height="400" alt="splunk forwoder" src="https://github.com/user-attachments/assets/af78052b-5147-4009-b3ed-a7138c53d869" />

<img width="1365" height="539" alt="UF splunk running" src="https://github.com/user-attachments/assets/0c2273f0-6c33-4d2c-9354-6763131f3bc0" />


Never commit passwords, deployment-server secrets, certificates, tokens, or environment-specific credentials to GitHub.
