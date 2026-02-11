## Incident Timeline – SOC Incident Case 001

### 2026-02-10 08:32:29 UTC
- **Event:** Outbound network connection detected
- **Source:** Sysmon Event ID 3
- **Details:** PowerShell established a TCP connection to 10.0.2.5:8000
- **Detection:** Elastic Security – Suspicious Outbound Network Connection (Non-Browser)

### 2026-02-10 08:32:30 UTC
- **Event:** Alert generated
- **Rule:** Suspicious Outbound Network Connection (Non-Browser)
- **Severity:** Medium
- **Risk Score:** 55

### 2026-02-10 08:35 UTC
- **Event:** Analyst investigation initiated
- **Action:** Reviewed process, user context, and destination IP
- **Assessment:** Activity confirmed as simulated attacker staging from Kali Linux host


## Initial Process Activity
- Multiple process execution events observed via Sysmon (Event ID 1).
- PowerShell execution identified as a recurring parent process.

## Explicit Credential Usage
- Windows Event ID 4648 detected.
- Explicit credentials used for account `testuser`.
- Activity consistent with `runas` usage.
- Indicates potential credential abuse or lateral movement preparation.

## Outbound Network Connection
- Sysmon Event ID 3 detected.
- Non-browser process (`powershell.exe`) initiated outbound TCP connection.
- Destination IP: 10.0.2.5
- Destination Port: 8000
- Behavior consistent with HTTP staging or command-and-control activity.

## Analyst Correlation
- Credential usage preceded outbound network activity.
- PowerShell acted as the execution and network pivot point.
- Activity chain suggests manual operator behavior rather than automated malware.


## Incident Timeline

**2026-02-11 04:24 UTC**
- Windows Security Event ID 4648 detected
- Explicit credentials used via `runas`
- Target account: testuser
- Source host: DESKTOP-MSCRJC2
- Risk: Potential credential misuse or privilege escalation

**2026-02-11 04:25 UTC**
- Sysmon Event ID 1 observed
- PowerShell process execution detected
- Command-line activity consistent with manual operator action

**2026-02-11 04:26 UTC**
- Sysmon Event ID 3 detected
- Non-browser process established outbound TCP connection
- Destination: 10.0.2.5:8000
- Process: powershell.exe
- Risk: Possible command-and-control or staging activity
