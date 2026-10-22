# Suspicious PowerShell Detection and Incident Investigation with Microsoft Sentinel

## Overview

This project demonstrates a complete Blue Team detection and investigation workflow using Microsoft Sentinel.

The objective was to simulate suspicious PowerShell activity on a Windows virtual machine, collect the relevant Windows security telemetry, detect the activity with KQL, create a scheduled analytics rule, and investigate the resulting Microsoft Sentinel incident.

The project focuses on practical SOC skills such as endpoint logging, threat hunting, detection engineering, MITRE ATT&CK mapping, alert generation, and incident investigation.

---

## Project Objectives

The main goals of the project were to:

- deploy a Windows endpoint in Azure;
- collect Windows Security Events using Azure Monitor Agent;
- enable Windows Process Creation auditing;
- generate controlled PowerShell activity;
- identify suspicious PowerShell execution using KQL;
- create a reusable detection rule;
- map the activity to MITRE ATT&CK;
- automatically generate a Microsoft Sentinel incident;
- investigate the affected host and user;
- document appropriate response and remediation steps.

---

## Lab Environment

The lab environment consisted of:

- Microsoft Azure
- Windows Server 2025 virtual machine
- Microsoft Sentinel
- Log Analytics Workspace
- Azure Monitor Agent
- Data Collection Rule
- Windows Security Event logs
- Kusto Query Language (KQL)

The Windows virtual machine was used as the monitored endpoint.

Windows Security Events were collected through Azure Monitor Agent and forwarded to the Log Analytics workspace used by Microsoft Sentinel.

---

## Architecture

The telemetry flow used in this project was:

```text
Windows VM
   |
   v
Windows Security Event Logs
   |
   v
Azure Monitor Agent
   |
   v
Data Collection Rule
   |
   v
Log Analytics Workspace
   |
   v
Microsoft Sentinel
   |
   +--> KQL Threat Hunting
   |
   +--> Analytics Rule
   |
   +--> Alert
   |
   v
Sentinel Incident
```

---

## Windows Telemetry Configuration

Process Creation auditing was enabled on the Windows endpoint in order to generate Event ID `4688`.

The following configuration was used:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

Command-line logging for process creation events was also enabled:

```powershell
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

The configuration was verified with:

```powershell
auditpol /get /subcategory:"Process Creation"
```

This allowed Microsoft Sentinel to receive process creation events containing the executed command line.

---

## Test Activity

Controlled PowerShell activity was generated on the monitored Windows endpoint.

A normal PowerShell command was executed first:

```powershell
powershell.exe -NoProfile -Command "Get-Process | Select-Object -First 5"
```

A second command used the `-EncodedCommand` argument:

```powershell
powershell.exe -NoProfile -EncodedCommand RwBlAHQALQBEAGEAdABlAA==
```

The encoded content decodes to:

```powershell
Get-Date
```

The command was intentionally harmless and was used only to generate telemetry that resembles suspicious PowerShell execution.

---

## Initial Log Validation

The first step was confirming that Windows Security Events were successfully reaching Microsoft Sentinel.

```kql
SecurityEvent
| take 20
```

Process creation events were then reviewed:

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where Process has_any ("powershell.exe", "pwsh.exe", "cmd.exe")
| project TimeGenerated, Computer, Account, Process, CommandLine
| order by TimeGenerated desc
```

This confirmed that process telemetry from the Windows VM was available for investigation.

---

## PowerShell Threat Hunt

PowerShell process creation events were filtered using Event ID `4688`.

```kql
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID == 4688
| where Process has "powershell.exe"
| project TimeGenerated, Computer, Account, Process, ParentProcessName, CommandLine
| order by TimeGenerated desc
```

The results showed the PowerShell activity generated on the endpoint.

---

## Suspicious PowerShell Detection

The query was then refined to search for specific command-line arguments commonly associated with suspicious PowerShell execution.

```kql
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID == 4688
| where Process has "powershell.exe"
| where CommandLine has_any ("EncodedCommand", "NoProfile")
| project TimeGenerated, Computer, Account, Process, ParentProcessName, CommandLine
| order by TimeGenerated desc
```

Both test commands were successfully identified.

---

## Detection Classification

To make the output easier to investigate, the query was extended to classify why an event was considered suspicious.

```kql
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID == 4688
| where Process has "powershell.exe"
| extend SuspiciousReason = case(
    CommandLine has "EncodedCommand", "Encoded PowerShell",
    CommandLine has "NoProfile", "PowerShell without profile",
    "Other"
)
| where SuspiciousReason != "Other"
| project TimeGenerated, Computer, Account, Process, SuspiciousReason, CommandLine
| order by TimeGenerated desc
```

This produced two classifications:

- Encoded PowerShell
- PowerShell without profile

---

## Microsoft Sentinel Analytics Rule

A scheduled analytics rule was created using the final detection logic.

### Rule Name

`Suspicious PowerShell Execution`

### Severity

`Medium`

### Detection Query

```kql
SecurityEvent
| where EventID == 4688
| where Process has "powershell.exe"
| extend SuspiciousReason = case(
    CommandLine has "EncodedCommand", "Encoded PowerShell",
    CommandLine has "NoProfile", "PowerShell without profile",
    "Other"
)
| where SuspiciousReason != "Other"
| project TimeGenerated, Computer, Account, Process, ParentProcessName, SuspiciousReason, CommandLine
```

### Rule Configuration

- Query frequency: 5 minutes
- Lookup period: 10 minutes
- Alert threshold: greater than 0 results
- Event grouping: one alert per event
- Incident creation: enabled
- Alert grouping: disabled

Entity mapping was configured for:

- Host
- Account

---

## MITRE ATT&CK Mapping

The detection was mapped to:

**Tactic:** Execution

**Technique:** Command and Scripting Interpreter

**Sub-technique:** PowerShell

**MITRE ATT&CK ID:** `T1059.001`

PowerShell is frequently used by both administrators and attackers. From a defensive perspective, command-line behavior and execution context must therefore be analyzed rather than treating PowerShell itself as malicious.

---

## Incident Generation

After the analytics rule was enabled, a new test PowerShell command using `-EncodedCommand` was executed.

The new Event ID `4688` was received by Sentinel and matched the analytics rule.

Microsoft Sentinel automatically generated an incident named:

`Suspicious PowerShell Execution`

The incident contained:

- Medium severity;
- Execution tactic;
- affected Windows host;
- affected user account;
- associated alert;
- host and account entity relationships.

This confirmed the complete detection pipeline:

```text
PowerShell Execution
        |
        v
Windows Event ID 4688
        |
        v
Azure Monitor Agent
        |
        v
Log Analytics
        |
        v
KQL Detection
        |
        v
Scheduled Analytics Rule
        |
        v
Alert
        |
        v
Microsoft Sentinel Incident
```

---

## Incident Investigation

The Sentinel investigation view was used to review the generated incident.

The investigation confirmed:

- the affected endpoint;
- the user account associated with the execution;
- the suspicious PowerShell command line;
- the related alert;
- the mapped MITRE ATT&CK tactic;
- the relationship between the affected user and host.

The generated activity in this lab was authorized and intentionally created for testing.

In a real SOC environment, the next step would be to determine whether the execution was expected administrative activity or part of a malicious sequence.

---

## Investigation Approach

An analyst investigating a similar alert should review:

1. The complete PowerShell command line.
2. The parent process that launched PowerShell.
3. The user account responsible for execution.
4. Other process creation events before and after the alert.
5. Authentication activity associated with the account.
6. Whether the same command appeared on additional endpoints.
7. Recently created users, services, scheduled tasks, or other persistence mechanisms.
8. Additional endpoint or identity telemetry related to the host.

The goal is to determine whether the PowerShell execution represents legitimate administration, automation, or malicious activity.

---

## Response and Remediation

If suspicious PowerShell activity is detected, the following response steps should be considered:

- Verify whether the execution was expected and authorized.
- Review the full command line, parent process, user account, and related events.
- Search for similar PowerShell activity across other endpoints.
- Review the affected system for additional suspicious processes.
- Investigate possible persistence mechanisms such as scheduled tasks, services, startup entries, or newly created accounts.
- Check authentication logs for evidence of account compromise.
- Preserve relevant logs and evidence for further investigation.

If malicious activity is confirmed:

- isolate the affected endpoint;
- terminate malicious processes where appropriate;
- disable or reset compromised accounts;
- remove identified persistence mechanisms;
- search the wider environment for related indicators;
- perform further incident response and forensic analysis.

---

## Detection Limitations

This detection identifies suspicious PowerShell characteristics but does not prove that malicious activity occurred.

For example:

- `-NoProfile` is commonly used by legitimate administrators and automation scripts;
- `-EncodedCommand` can also be used for legitimate purposes;
- PowerShell is widely used for normal system administration.

Because of this, alerts generated by this rule require additional investigation.

In a production environment, the detection should be correlated with additional context such as:

- parent process;
- command content;
- user behavior;
- execution frequency;
- endpoint history;
- authentication activity;
- PowerShell Script Block Logging;
- EDR telemetry;
- network activity;
- known administrative scripts.

Known-good administrative activity could also be excluded after establishing an appropriate baseline.

---

## Key Findings

This project demonstrated that suspicious PowerShell behavior can be detected using native Windows process creation telemetry and Microsoft Sentinel.

The most important outcome was not simply detecting the use of PowerShell, but building a complete workflow from endpoint activity to an actionable security incident.

The lab demonstrated practical experience with:

- Windows Security Events;
- Event ID 4688;
- endpoint logging;
- Azure Monitor Agent;
- Data Collection Rules;
- Microsoft Sentinel;
- Log Analytics;
- KQL threat hunting;
- detection engineering;
- scheduled analytics rules;
- entity mapping;
- MITRE ATT&CK;
- incident investigation;
- response planning.

---

## Screenshots

The repository contains screenshots documenting the main stages of the investigation.

```text
screenshots/
├── 01-resource-group-overview.png
├── 02-vm-overview.png
├── 03-nsg-rdp-restriction.png
├── 04-sentinel-workspace-overview.png
├── 05-dcr-windows-security-events.png
├── 06-securityevent-logs.png
├── 07-initial-kql-process-hunt.png
├── 08-powershell-test-activity.png
├── 09-powershell-process-events.png
├── 10-suspicious-powershell-hunt.png
├── 11-powershell-detection-classification.png
├── 12a-analytics-rule-detection-logic.png
├── 12b-analytics-rule-scheduling.png
├── 13-suspicious-powershell-incident.png
├── 14-incident-investigation-view.png
└── 15-incident-summary.png
```

Sensitive Azure information such as subscription identifiers, public IP addresses, and unnecessary account information should be redacted before screenshots are published.

---

## Repository Structure

```text
sentinel-powershell-detection-and-response/
│
├── README.md
├── incident-report.md
│
├── queries/
│   └── powershell-detection.kql
│
└── screenshots/
    ├── 01-resource-group-overview.png
    ├── 02-vm-overview.png
    ├── 03-nsg-rdp-restriction.png
    ├── 04-sentinel-workspace-overview.png
    ├── 05-dcr-windows-security-events.png
    ├── 06-securityevent-logs.png
    ├── 07-initial-kql-process-hunt.png
    ├── 08-powershell-test-activity.png
    ├── 09-powershell-process-events.png
    ├── 10-suspicious-powershell-hunt.png
    ├── 11-powershell-detection-classification.png
    ├── 12a-analytics-rule-detection-logic.png
    ├── 12b-analytics-rule-scheduling.png
    ├── 13-suspicious-powershell-incident.png
    ├── 14-incident-investigation-view.png
    └── 15-incident-summary.png
```

---

## Skills Demonstrated

- Microsoft Sentinel
- Kusto Query Language
- Windows Security Event analysis
- Threat hunting
- Detection engineering
- Security monitoring
- Incident investigation
- MITRE ATT&CK
- Windows process auditing
- Azure Monitor Agent
- Log Analytics
- Data Collection Rules
- Basic incident response

---

## Future Improvements

Possible improvements to the detection include:

- enabling PowerShell Script Block Logging;
- incorporating Event ID `4104`;
- correlating PowerShell activity with authentication events;
- analyzing suspicious parent-child process relationships;
- adding allowlists for approved administrative activity;
- incorporating Microsoft Defender for Endpoint telemetry;
- adding behavioral correlation across multiple events;
- developing automated enrichment or triage through Microsoft Sentinel automation.

These improvements would reduce false positives and provide stronger behavioral context during investigation.

---

## Conclusion

This project demonstrates a complete security monitoring workflow rather than an isolated detection query.

A controlled PowerShell execution was generated on a Windows endpoint, captured through Windows Security auditing, collected in Microsoft Sentinel, analyzed with KQL, converted into a scheduled detection rule, and investigated as a Sentinel incident.

The project provided hands-on experience with the core activities performed in SOC and Blue Team environments: collecting telemetry, identifying suspicious behavior, building detections, investigating alerts, mapping behavior to MITRE ATT&CK, and defining appropriate response actions.
