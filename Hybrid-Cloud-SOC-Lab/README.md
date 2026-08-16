# Hybrid Cloud SOC Lab

This project documents the design, deployment, validation, and detection-engineering workflow of a hands-on SOC lab built around Windows telemetry, Sysmon, Splunk Universal Forwarder, and Splunk Enterprise.

## Current Implemented Pipeline

```text
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
        | Indexing -> SPL detections -> Alerts
        v
[ SOC Analyst Dashboard ]
```

## Planned Final Extension

```text
[ Kali Linux - GCP ]
        |
        | Controlled attack simulation
        | via Tailscale VPN
        v
[ Windows 10 VM ] -> Sysmon -> Universal Forwarder -> Splunk -> SOC Dashboard
```

The Kali Linux / GCP / Tailscale layer is intentionally documented as a planned extension until it is fully deployed and validated.

## Setup Documentation

Follow the setup in this order:

1. [Windows VM Setup](./Setup/01-Windows-VM-Setup.md)
2. [Sysmon Installation and Configuration](./Setup/02-Sysmon-Installation.md)
3. [Splunk Enterprise Setup](./Setup/03-Splunk-Enterprise-Setup.md)
4. [Splunk Universal Forwarder Setup](./Setup/04-Universal-Forwarder-Setup.md)
5. [Sysmon Log Onboarding into Splunk](./Setup/05-Splunk-Log-Onboarding.md)
6. [End-to-End Validation Checklist](./Setup/06-End-to-End-Validation.md)

See [Architecture](./Architecture.md) for the complete data-flow design.

## Detection Engineering

PowerShell detection engineering is maintained under:

- [Detection Engineering / PowerShell](./Detection_Engineering/PowerShell/README.md)

The detection workflow is:

**Generate controlled activity -> confirm Sysmon telemetry -> validate SPL -> create alert -> verify trigger -> tune noise/scheduling -> document evidence**

## Security Notes

Do not commit passwords, authentication tokens, Tailscale auth keys, Splunk credentials, private keys, or other secrets to this repository. Use placeholders such as `<SPLUNK_SERVER_IP>` and `<TAILSCALE_IP>` in public documentation.
