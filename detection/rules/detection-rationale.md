# Detection Engineering Rationale

## Rule 1: Explicit Credential Use (Event ID 4648)

**Description**
Detects Windows Security Event ID 4648, which occurs when a process attempts to log on using explicitly supplied credentials.

**Why This Matters**
Event ID 4648 is commonly associated with:
- `runas` usage
- Scheduled task abuse
- Insider misuse
- Credential abuse and lateral movement

This event is especially valuable because it captures credential usage **before** a successful or failed logon event (4624/4625).

**Threat Mapping**
- MITRE ATT&CK: T1078 (Valid Accounts)
- MITRE ATT&CK: T1550 (Use Alternate Authentication Material)

---

## Rule 2: Sysmon Process Execution (Event ID 1)

**Description**
Detects all process creation events on the host.

**Why This Matters**
Process creation telemetry provides visibility into:
- Living-off-the-land binaries (LOLBins)
- PowerShell abuse
- Initial attacker execution

This rule was intentionally configured as low severity to support triage and investigation workflows.

**Threat Mapping**
- MITRE ATT&CK: T1059 (Command and Scripting Interpreter)

---

## Rule 3: Suspicious Outbound Network Connection (Sysmon Event ID 3)

**Description**
Detects non-browser processes initiating outbound network connections on uncommon ports.

**Why This Matters**
Attackers frequently use:
- PowerShell
- cmd.exe
- custom binaries

to communicate with staging servers or command-and-control infrastructure over non-standard ports.

Browser traffic is excluded to reduce false positives.

**Threat Mapping**
- MITRE ATT&CK: T1071 (Application Layer Protocol)
- MITRE ATT&CK: T1105 (Ingress Tool Transfer)
