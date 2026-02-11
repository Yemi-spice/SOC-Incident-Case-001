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

