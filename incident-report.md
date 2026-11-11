# Incident Report: Suspicious PowerShell Execution

## Incident summary

Microsoft Sentinel generated a Medium-severity incident after detecting encoded PowerShell execution on the monitored Windows endpoint.

Analytics rule:

`Suspicious PowerShell Execution`

The activity was generated intentionally in a controlled lab environment for detection-engineering and incident-investigation testing.

Final classification:

`Benign Positive — authorized security testing`

## Affected assets

Host:

`win-blue-team-lab`

User:

`azureuser`

The incident associated the affected user with the monitored Windows endpoint.

## Detection source

The detection was based on:

`Windows Security Event ID 4688 — A new process has been created`

Process Creation auditing and command-line logging were enabled before the test activity was generated.

Telemetry was collected through:

- Windows Security auditing;
- Azure Monitor Agent;
- Data Collection Rule;
- Log Analytics;
- Microsoft Sentinel.

## Controlled test activity

Two PowerShell commands were generated.

### Control case

```powershell
powershell.exe -NoProfile -Command "Get-Process | Select-Object -First 5"
```

This command used `-NoProfile` but did not use encoded execution.

### Positive case

```powershell
powershell.exe -NoProfile -EncodedCommand RwBlAHQALQBEAGEAdABlAA==
```

The encoded content decoded to:

```powershell
Get-Date
```

Both executions generated Event ID `4688` process-creation telemetry.

## Detection tuning

The initial detection treated both of the following as suspicious:

- `-NoProfile`
- `-EncodedCommand`

Testing showed that this logic was too broad.

`-NoProfile` is commonly used in legitimate PowerShell administration and scripting, so it was removed as a standalone alert condition.

The final detection now alerts on encoded PowerShell execution.

`-NoProfile` is retained only as investigation context.

## Final detection logic

The final query:

1. filters for Event ID `4688`;
2. identifies `powershell.exe` and `pwsh.exe`;
3. normalizes process and command-line values;
4. detects encoded-command usage;
5. records whether `-NoProfile` is present;
6. generates results only when encoded execution is detected.

The complete current detection query is stored in:

[`queries/powershell-detection.kql`](queries/powershell-detection.kql)

Keeping the query in a dedicated file avoids duplicating detection logic across the repository.

## Investigation findings

The investigation confirmed that:

- PowerShell executed on `win-blue-team-lab`;
- Windows generated Event ID `4688`;
- command-line information was available in Sentinel;
- the positive test contained encoded PowerShell execution;
- the control test used `-NoProfile` without encoded execution;
- the tuned rule preserved detection of the encoded command;
- the `NoProfile`-only control case was no longer treated as sufficient for detection;
- Microsoft Sentinel generated the expected incident;
- no malicious payload was executed.

The encoded payload contained only:

`Get-Date`

## MITRE ATT&CK mapping

Tactic:

`Execution`

Technique:

`T1059 — Command and Scripting Interpreter`

Sub-technique:

`T1059.001 — PowerShell`

PowerShell itself is not malicious. The rule focuses on a command-line behavior that increases investigation priority.

## Analyst assessment

Encoded PowerShell can be used legitimately, but it can also make command content less immediately visible to an analyst.

A detection should therefore trigger investigation rather than automatically proving malicious activity.

Relevant context includes:

- complete command line;
- decoded PowerShell content;
- parent process;
- user account;
- recent authentication activity;
- related process creation;
- network connections;
- file creation;
- endpoint history;
- PowerShell Script Block Logging;
- EDR telemetry.

In this lab, the encoded command was harmless and intentionally generated.

## Final classification

**Classification:** Benign Positive

**Reason:** Authorized security testing intentionally generated the encoded PowerShell activity.

**Severity:** Medium

**Status:** Investigation completed

## Recommended response

For a similar production incident, an analyst should:

1. Review the complete PowerShell command line.
2. Decode encoded content in a safe analysis environment.
3. Identify the parent process.
4. Validate the user and host involved.
5. Review related authentication events.
6. Search for additional PowerShell activity.
7. Check for child processes and file creation.
8. Review network activity.
9. Check for persistence mechanisms.
10. Determine whether the execution was authorized.

If malicious activity is confirmed, possible response actions include:

- isolating the affected endpoint;
- terminating malicious processes;
- disabling or resetting compromised accounts;
- removing persistence;
- hunting for related activity across other systems;
- preserving logs and forensic evidence;
- continuing incident response.

## Detection limitations

The final rule intentionally focuses on encoded PowerShell execution.

Possible legitimate matches include:

- administration scripts;
- software deployment tools;
- endpoint-management platforms;
- automation systems;
- approved encoded PowerShell commands.

Current limitations include:

- encoded execution alone does not establish malicious intent;
- payload content is not automatically decoded by the detection;
- parent-process context is not part of the alert condition;
- user and host baselines are not included;
- network behavior is not correlated;
- PowerShell Script Block Logging is not included.

Production improvements could include:

- Event ID `4104` Script Block Logging;
- automated encoded-command decoding;
- parent-child process correlation;
- approved-script baselines;
- user and host baselines;
- Defender for Endpoint telemetry;
- network correlation;
- suspicious PowerShell behavior scoring.

## What changed after testing

| Finding | Change |
|---|---|
| `NoProfile` generated unnecessary detection noise | Removed it as a standalone alert condition |
| `NoProfile` still provides useful context | Retained it as an output field |
| Detection focused only on Windows PowerShell | Added `pwsh.exe` support |
| Command comparison could vary by case | Normalized process and command-line values |
| Positive and control cases were mixed together | Separated encoded execution from benign control activity |

## Outcome

The final workflow was:

```text
PowerShell Process Creation
        |
        v
Event ID 4688
        |
        v
Command-Line Collection
        |
        v
EncodedCommand Detection
        |
        v
Sentinel Analytics Rule
        |
        v
Incident
        |
        v
Analyst Investigation
        |
        v
Benign Positive Classification
```

The tuned rule reduced unnecessary noise from `-NoProfile` while preserving detection of the encoded PowerShell test activity.
