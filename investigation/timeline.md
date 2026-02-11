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

