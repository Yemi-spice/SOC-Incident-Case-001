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
