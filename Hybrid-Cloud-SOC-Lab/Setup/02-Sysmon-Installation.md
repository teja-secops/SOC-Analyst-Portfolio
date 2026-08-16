# 02 - Sysmon Installation and Configuration

## Objective

Install Sysmon on the Windows endpoint and collect the endpoint telemetry required by the Splunk detection rules.

## Telemetry Used in This Lab

The primary Sysmon events used by the project are:

- Event ID 1 - Process Creation
- Event ID 3 - Network Connection

Process-creation telemetry is used heavily by the current PowerShell detection set. Network telemetry will also support later LOLBin and attack-simulation detections.

## Installation

Download Sysmon from Microsoft Sysinternals and place the executable and the selected Sysmon configuration file in a controlled lab directory.

Open an elevated Command Prompt in that directory and install Sysmon with the configuration:

```cmd
Sysmon64.exe -accepteula -i sysmonconfig.xml
```

If Sysmon is already installed and the configuration needs to be updated:

```cmd
Sysmon64.exe -c sysmonconfig.xml
```

## Service Verification

Check that the Sysmon service is running:

```cmd
sc query Sysmon64
```

The service state should show `RUNNING`.

## Event Viewer Verification

Open:

```text
Event Viewer
  -> Applications and Services Logs
  -> Microsoft
  -> Windows
  -> Sysmon
  -> Operational
```

Generate a harmless process event, for example:

```cmd
hostname
```

Confirm that a new Sysmon Event ID 1 appears.

For Event ID 3 validation, confirm the active Sysmon configuration includes network-connection logging and generate a normal outbound connection. The event should appear only when Event ID 3 collection is enabled by the configuration.

## Why Sysmon Is Used

Default Windows logs provide useful security telemetry, but Sysmon adds richer process and network context such as:

- Executable image path
- Command line
- Parent process
- User context
- Process identifiers
- Destination network information for enabled network events

These fields improve detection engineering and analyst triage in Splunk.

## Important Configuration Note

Sysmon Event ID 3 can be noisy. In a larger environment it should be filtered and tuned. In this home lab it is enabled to support network-oriented detection validation.

## Validation Checklist

- [ ] Sysmon installed successfully
- [ ] Sysmon64 service is running
- [ ] Sysmon Operational log exists
- [ ] Event ID 1 is generated for process creation
- [ ] Event ID 3 is available when enabled by the config
- [ ] Endpoint is ready for Universal Forwarder onboarding

## Security Note
<img width="1365" height="731" alt="sysmon" src="https://github.com/user-attachments/assets/652b447f-1c05-43cd-81eb-12ab6bc6b972" />

Do not publish any configuration containing environment-specific secrets. Sysmon configuration files normally contain detection filters rather than credentials, but they should still be reviewed before being committed publicly.
