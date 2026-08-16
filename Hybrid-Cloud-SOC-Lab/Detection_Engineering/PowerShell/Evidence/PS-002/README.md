# PS-002 Evidence — PowerShell Encoded Command

Evidence for PS-002 should include:

1. Splunk search results showing Sysmon Event ID 1 events matching `-EncodedCommand` or `-enc`.
2. Triggered Alerts view showing `SOC - PowerShell Encoded Command Detected`.

## Validation observed

- Controlled encoded PowerShell test executed in the lab.
- Splunk returned 5 matching events during validation.
- High-severity alert triggered successfully.

> Screenshots should be added to this folder after checking that they do not expose sensitive credentials, tokens, license keys, or other private information.
