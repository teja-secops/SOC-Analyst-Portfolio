# 01 - Windows VM Setup

## Objective

Prepare the Windows endpoint that will act as the monitored system for the SOC lab.

## Role in the Lab

```text
[ Windows 10 VM ]
      |
      | endpoint telemetry
      v
[ Sysmon ] -> [ Splunk Universal Forwarder ] -> [ Splunk Enterprise ]
```

## Base Requirements

- Windows 10 VM
- Administrative access inside the VM
- Stable network connectivity to the Splunk Enterprise host
- Sufficient free disk space for Windows event logs, Sysmon, and the Universal Forwarder
- System clock synchronized

## VirtualBox Networking

During lab troubleshooting, a stable host-to-VM path was required for forwarding telemetry. A Host-Only Adapter can be used for the Splunk forwarding path so the Windows VM can consistently reach the Splunk Enterprise host without depending on changing Wi-Fi addresses.

Recommended design:

```text
Windows VM
   |
   | Host-Only network
   v
Splunk Enterprise host
```

A separate NAT adapter may be retained when the VM requires normal internet access for updates or package downloads.

## Connectivity Validation

From the Windows VM, identify the interface configuration:

```cmd
ipconfig
```

Verify the Splunk host is reachable:

```cmd
ping <SPLUNK_SERVER_IP>
```

Later, after the Splunk receiving port is configured, validate TCP 9997 from PowerShell:

```powershell
Test-NetConnection <SPLUNK_SERVER_IP> -Port 9997
```

Expected result:

```text
TcpTestSucceeded : True
```

## Windows Firewall

Allow only the connectivity required for the lab. The Windows endpoint does not need to expose Splunk port 9997 because it acts as the forwarding client; the receiving port is opened on the Splunk Enterprise system.

## Lab Safety

This VM is used for controlled security testing. Keep personal or production credentials and sensitive files outside the lab VM.

## Validation Checklist

- [ ] Windows VM boots normally
- [ ] Administrator access works
- [ ] VM has a stable IP on the lab network
- [ ] Splunk Enterprise host is reachable
- [ ] System time is correct
- [ ] VM is ready for Sysmon installation

<img width="1358" height="729" alt="orcale vm" src="https://github.com/user-attachments/assets/2e16f3d8-6e58-4087-80fe-bcec0221bff1" />

