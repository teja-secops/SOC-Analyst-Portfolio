# PS-002 Evidence — PowerShell Encoded Command

Evidence for PS-002 should include:

1. Splunk search results showing Sysmon Event ID 1 events matching `-EncodedCommand` or `-enc`.
2. Triggered Alerts view showing `SOC - PowerShell Encoded Command Detected`.

## Validation observed

- Controlled encoded PowerShell test executed in the lab.
- Splunk returned 5 matching events during validation.
- High-severity alert triggered successfully.

<img width="1358" height="634" alt="SPL query results" src="https://github.com/user-attachments/assets/6fc7c664-a7df-4865-89a2-c234eac6aa65" />


<img width="1361" height="331" alt="Triggered alerts" src="https://github.com/user-attachments/assets/ee5a82ad-8072-428a-9b47-8eacf43eac58" />

