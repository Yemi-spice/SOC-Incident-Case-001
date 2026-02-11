# SOC Alert Triage Playbook

This document outlines the triage process used to investigate alerts generated
during SOC-Incident-Case-001. The goal is to demonstrate structured SOC thinking,
not just tool usage.

---

## Alert Type 1: Explicit Credential Use (Event ID 4648)

### Alert Summary
- **Rule Name:** Explicit Credential Use Detected (Event ID 4648)
- **Severity:** Medium
- **MITRE Technique:** T1078 – Valid Accounts
- **Common Use Cases:** runas, scheduled tasks, lateral movement, credential abuse

---

### Initial Triage Questions
1. Which user initiated the credential use?
2. Was the target account privileged?
3. Was this interactive or scripted?
4. Is the source host expected to perform this action?

---

### Key Fields to Review
- `winlog.event_data.SubjectUserName`
- `winlog.event_data.TargetUserName`
- `winlog.event_data.ProcessName`
- `winlog.event_data.LogonType`
- `host.name`
- `@timestamp`

---

### Investigation Steps
1. Validate the process responsible for the credential usage.
2. Check for repeated attempts or failures (4625).
3. Correlate with process creation (Sysmon Event ID 1).
4. Review recent activity from the same user and host.

---

### Determination
- **True Positive / False Positive:** TBD
- **Reasoning:** Pending further correlation

---

### Response Actions
- Monitor account activity
- Validate legitimacy with user (if enterprise context)
- Escalate if correlated with suspicious process or network activity

---

## Notes
This alert was generated intentionally during lab testing using the `runas` command.

---

## Alert Type 2: Suspicious Outbound Network Connection (Sysmon Event ID 3)

### Alert Summary
- **Rule Name:** Suspicious Outbound Network Connection (Non-Browser)
- **Severity:** Medium
- **MITRE Technique:** T1071 – Application Layer Protocol
- **Common Use Cases:** C2 beaconing, payload download, staging server access

---

### Initial Triage Questions
1. What process initiated the network connection?
2. Is the destination IP internal or external?
3. Is the destination port commonly used?
4. Does the process normally make network connections?

---

### Key Fields to Review
- `winlog.event_data.Image`
- `winlog.event_data.DestinationIp`
- `winlog.event_data.DestinationPort`
- `winlog.event_data.Protocol`
- `winlog.event_data.SourceIp`
- `user.name`

---

### Investigation Steps
1. Identify the initiating process (e.g., PowerShell).
2. Validate whether the destination IP is expected.
3. Check for repeated connections to the same destination.
4. Correlate with process creation (Sysmon Event ID 1).
5. Check for related credential usage (Event ID 4648).

---

### Determination
- **True Positive / False Positive:** True Positive
- **Reasoning:** Non-browser process (PowerShell) connected to a non-standard port (8000)
  associated with a staging HTTP server hosted on Kali Linux.

---

### Response Actions
- Block outbound connection (enterprise scenario)
- Investigate command-line arguments
- Contain host if additional malicious activity is detected

---

## Notes
This alert was triggered intentionally using a Python HTTP server hosted on Kali
and accessed via PowerShell from the Windows host.


---

## Alert Type 3: Process Execution (Sysmon Event ID 1)

### Alert Summary
- **Rule Name:** TEST – Sysmon Process Execution (EID 1)
- **Severity:** Low
- **MITRE Technique:** T1059 – Command and Scripting Interpreter
- **Common Use Cases:** Execution of scripts, binaries, attacker tooling

---

### Initial Triage Questions
1. What process was executed?
2. Who executed it?
3. Was it user-initiated or system-initiated?
4. Is the command-line suspicious or encoded?

---

### Key Fields to Review
- `winlog.event_data.Image`
- `winlog.event_data.CommandLine`
- `winlog.event_data.ParentImage`
- `user.name`
- `host.name`

---

### Investigation Steps
1. Review the command-line arguments.
2. Identify parent-child process relationships.
3. Check for encoded or obfuscated commands.
4. Correlate with network connections (Sysmon Event ID 3).

---

### Determination
- **True Positive / False Positive:** Context-dependent
- **Reasoning:** Process execution alone is not malicious; intent is determined
  through correlation with other alerts.

---

### Response Actions
- No immediate action if isolated
- Escalate if correlated with credential misuse or outbound connections

---

## Notes
This rule is intentionally noisy and used as a correlation signal rather than
a standalone detection.
