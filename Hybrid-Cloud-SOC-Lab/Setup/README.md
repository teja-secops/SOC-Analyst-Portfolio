# SOC Lab Setup Documentation

This folder contains the reproducible setup documentation for the implemented SOC telemetry pipeline.

## Build Order

1. [Windows VM Setup](./01-Windows-VM-Setup.md)
2. [Sysmon Installation and Configuration](./02-Sysmon-Installation.md)
3. [Splunk Enterprise Setup](./03-Splunk-Enterprise-Setup.md)
4. [Splunk Universal Forwarder Setup](./04-Universal-Forwarder-Setup.md)
5. [Sysmon Log Onboarding into Splunk](./05-Splunk-Log-Onboarding.md)
6. [End-to-End Validation](./06-End-to-End-Validation.md)

## Implemented Data Flow

```text
Windows 10 VM
   -> Sysmon
   -> Splunk Universal Forwarder
   -> TCP 9997
   -> Splunk Enterprise
   -> SPL detections
   -> Triggered Alerts / SOC Dashboard
```

## Next Phase

After the current pipeline is fully documented and revalidated, the lab will be extended with:

```text
Kali Linux (GCP)
   -> Tailscale VPN
   -> Windows 10 VM
```

That layer will be documented separately only after it is actually deployed and tested.

## Documentation Standard

Each setup guide records:

- Purpose of the component
- Configuration steps
- Validation commands/searches
- Troubleshooting checks
- Security considerations

Public documentation uses placeholders for environment-specific information and never stores credentials or authentication secrets.
