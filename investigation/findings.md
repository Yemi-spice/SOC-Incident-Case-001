## Finding 001 – Suspicious Outbound Network Connection via PowerShell

### Summary
A Windows endpoint initiated an outbound TCP connection to a non-standard port (8000) using PowerShell, bypassing standard browser applications. This behavior is consistent with payload staging or command-and-control activity.

### Detection Source
- Elastic Security
- Sysmon Event ID 3 (Network connection)
- Custom detection rule: Suspicious Outbound Network Connection (Non-Browser)

### Affected Host
- Hostname: DESKTOP-MSCRJC2
- User: DESKTOP-MSCRJC2\Local-cafe

### Network Indicators
- Source IP: 10.0.2.4
- Destination IP: 10.0.2.5
- Destination Port: 8000
- Protocol: TCP

### Process Indicators
- Process Name: powershell.exe
- Process Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

### Analyst Assessment
The use of PowerShell to initiate an outbound connection over a non-standard port strongly suggests suspicious activity. In this lab scenario, the destination IP was confirmed to be a staging server hosted on a Kali Linux system.

### Severity
Medium


## Explicit Credential Use Detection (Event ID 4648)

Elastic Security detected Windows Event ID 4648, indicating the use of explicit credentials on the host.

### Key Observations
- **Logon Type:** Explicit credentials (runas behavior)
- **Target User:** testuser
- **Process Context:** svchost.exe (seclogo)
- **Source Address:** ::1 (local)
- **Detection Rule:** Explicit Credential Use Detected (Event ID 4648)
- **Severity:** Medium
- **Risk Score:** 50

### Analyst Assessment
The activity is consistent with credential usage via the `runas` command. While locally generated in this lab, similar behavior is commonly observed during lateral movement, privilege escalation attempts, or persistence activity in real-world intrusions.



# Incident Findings — SOC-Incident-Case-001

## Incident Classification
**Type:** Insider Misuse  
**Severity:** Medium  
**Confidence:** High  

## Summary
The investigation identified suspicious internal activity involving explicit credential usage followed by outbound network connections initiated via PowerShell. The activity originated from a legitimate user account and did not rely on malware, indicating potential insider misuse or policy violation.

## Key Observations

### Explicit Credential Usage
- Windows Security Event ID 4648 detected.
- Account `testuser` credentials explicitly used via `runas`.
- Indicates manual authentication attempt rather than automated process.
- Common in privilege escalation or account misuse scenarios.

### Process Execution
- Multiple Sysmon Event ID 1 entries observed.
- PowerShell used as the primary execution context.
- Behavior aligns with living-off-the-land techniques.

### Network Activity
- Sysmon Event ID 3 captured outbound TCP connection.
- Destination IP: `10.0.2.5`
- Destination Port: `8000`
- Non-browser process used for HTTP communication.
- Pattern consistent with staging, testing, or unauthorized data transfer.

## Impact Assessment
- No evidence of malware persistence.
- No confirmed data exfiltration.
- Elevated risk due to credential misuse and unsanctioned network activity.

## Analyst Assessment
The activity chain strongly suggests insider misuse involving credential abuse and unauthorized network communication. While no destructive actions were observed, the behavior represents a policy violation and potential security risk requiring containment and user review.
