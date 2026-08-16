# 03 - Splunk Enterprise Setup

## Objective

Configure Splunk Enterprise as the central SIEM receiver, search platform, and alerting engine for the SOC lab.

## Role in the Lab

```text
Windows VM
   -> Sysmon
   -> Splunk Universal Forwarder
   -> TCP 9997
   -> Splunk Enterprise
   -> Detection Searches / Alerts / Dashboard
```

## Splunk Web

The Splunk Web interface is available on the default web port:

```text
http://<SPLUNK_SERVER_IP>:8000
```

For a local installation on the Splunk host, `http://localhost:8000` can also be used.

## Configure the Receiving Port

In Splunk Web:

```text
Settings
  -> Forwarding and receiving
  -> Configure receiving
  -> New Receiving Port
```

Configure:

```text
Port: 9997
```

The Universal Forwarder will send Windows/Sysmon telemetry to this port.

## Verify the Receiver

After saving the receiving port, confirm that TCP 9997 is listening on the Splunk host.

From the Windows endpoint, test connectivity:

```powershell
Test-NetConnection <SPLUNK_SERVER_IP> -Port 9997
```

Expected result:

```text
TcpTestSucceeded : True
```

## Create / Use the Sysmon Index

The current detection content uses:

```spl
index=sysmon
```

Ensure the `sysmon` index exists before forwarding data into it.

In Splunk Web:

```text
Settings
  -> Indexes
```

Create the index if it is not already present:

```text
Index name: sysmon
```

## Initial Search Validation

Once forwarding is configured, use:

```spl
index=sysmon
| stats count by host
```

Then validate process events:

```spl
index=sysmon EventCode=1
| table _time host User Image ParentImage CommandLine
| sort - _time
```

For Sysmon network telemetry:

```spl
index=sysmon EventCode=3
| table _time host Image DestinationIp DestinationPort Protocol
| sort - _time
```

## Alerting Role

Splunk Enterprise is used in this project to:

- Parse and index endpoint telemetry
- Run optimized SPL detection searches
- Create scheduled alerts
- Add fired detections to Triggered Alerts
- Feed the SOC analyst dashboard
- Support investigation using raw and normalized event fields

## Scheduler Note

During detection development, multiple frequent scheduled searches can create scheduler contention in a small lab instance. Validation schedules should be temporary and later staggered or reduced after a detection is confirmed.

## Validation Checklist

- [ ] Splunk Enterprise service is running
- [ ] Splunk Web loads on port 8000
- [ ] `sysmon` index exists
- [ ] Receiving port 9997 is configured
- [ ] Windows endpoint can reach TCP 9997
- [ ] Forwarded events are searchable
- [ ] Detection searches can run successfully

## Security Notes
<img width="1365" height="662" alt="splunk dashboard" src="https://github.com/user-attachments/assets/d9d8b7ff-e385-4d97-adea-9f5b86aa25a8" />

Never commit Splunk administrator passwords, authentication tokens, license files, or private deployment details to the public repository. Use placeholders such as `<SPLUNK_SERVER_IP>` in documentation.
