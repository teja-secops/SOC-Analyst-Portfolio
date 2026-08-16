# PowerShell SPL Query Optimization

For better search performance in the lab, filters were moved into the base search wherever possible instead of retrieving a broader Sysmon EventCode 1 dataset and applying multiple post-search filters afterward.

Example pattern used:

```spl
index=sysmon EventCode=1 Image="*process.exe" CommandLine="*suspicious-pattern*"
| eval Detection="Detection Name"
| eval Severity="Medium"
| eval MITRE="Technique ID - Technique Name"
| table _time host User ParentImage Image CommandLine Detection Severity MITRE
| sort - _time
```

This format also enriches the result set with detection name, severity, and MITRE ATT&CK context so the output is easier to review during SOC investigations and portfolio demonstrations.

Current optimized PowerShell detections:

- PS-001 — PowerShell Execution
- PS-002 — PowerShell Encoded Command
- PS-003 — PowerShell Execution Policy Bypass
