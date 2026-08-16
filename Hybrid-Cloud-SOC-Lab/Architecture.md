# SOC Lab Architecture

## Implemented Architecture

```text
[ Windows 10 VM ]
   |  Controlled PowerShell / LOLBin activity
   |
   |  Sysmon telemetry
   |  Event ID 1 - Process Creation
   |  Event ID 3 - Network Connection
   v
[ Splunk Universal Forwarder ]
   |
   |  Near real-time forwarding
   |  TCP 9997
   v
[ Splunk Enterprise ]
   |  Parsing and indexing
   |  SPL detection searches
   |  Scheduled alert generation
   v
[ SOC Analyst Dashboard ]
      Low / Medium / High alerts
```

## Planned Final Architecture

```text
[ Kali Linux - GCP ]
        |
        | Controlled attack simulation
        | via Tailscale private VPN tunnel
        v
[ Windows 10 VM ]
        |
        | Sysmon Event IDs 1 and 3
        v
[ Splunk Universal Forwarder ]
        |
        | TCP 9997
        v
[ Splunk Enterprise ]
        |
        | Detection and alerting
        v
[ SOC Analyst Dashboard ]
```

## Component Roles

### Windows 10 VM
The Windows endpoint is the telemetry source and controlled target system. Test activity is executed only for lab validation.

### Sysmon
Sysmon provides detailed endpoint telemetry. The primary data used by this project includes process creation and network-connection events.

### Splunk Universal Forwarder
The Universal Forwarder runs on the Windows endpoint and forwards selected Windows event channels to the Splunk Enterprise receiver.

### Splunk Enterprise
Splunk receives telemetry on TCP port 9997, indexes the events, executes SPL detection logic, and generates alerts.

### SOC Analyst Dashboard
The dashboard provides a central view of triggered detections and supports analyst triage and investigation.

### Kali Linux / GCP / Tailscale
This layer is the next implementation phase. Once validated, Kali Linux in GCP will be used as a controlled simulation host connected to the Windows lab through Tailscale rather than exposing the Windows VM directly to the public internet.

## Data Flow

```text
Endpoint activity
   -> Sysmon collection
   -> Universal Forwarder
   -> TCP 9997
   -> Splunk index
   -> SPL detection
   -> Alert
   -> Analyst investigation
```

## Ports

| Port | Purpose |
|---|---|
| 8000/TCP | Splunk Web interface |
| 9997/TCP | Splunk receiving port for forwarders |

Only the ports required by the lab should be permitted. Public exposure of the Splunk receiver or Windows endpoint is not required for the local telemetry pipeline.
