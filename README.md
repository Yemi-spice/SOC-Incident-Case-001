# SOC Incident Case 001 — Credential Misuse & Suspicious PowerShell (Elastic SIEM Lab)

## TL;DR
Built a small SOC lab (Windows + Ubuntu Elastic Stack + Kali attacker) and generated real telemetry (Sysmon + Windows Security logs) into Elasticsearch via Winlogbeat. Investigated suspicious activity including explicit credential usage (Event ID 4648), failed logons (4625), user creation (4720), and encoded PowerShell execution (Sysmon Event ID 1).

## Lab Architecture
- **Windows 10 (Victim/Telemetry):** Sysmon + Winlogbeat
- **Ubuntu (SIEM):** Elasticsearch + Kibana (Elastic Security)
- **Kali (Attacker):** network recon + service probing (lab testing)

## What I Implemented
- Installed and validated **Sysmon logging** (Process Create, Network, DNS, File Create).
- Configured **Winlogbeat** to ship:
  - Application, Security, System
  - Microsoft-Windows-Sysmon/Operational
- Verified ingestion in Kibana Discover and pivoted on key events:
  - **Sysmon EID 1** (process creation) for PowerShell + encoded commands
  - **Security 4648** (explicit credentials via `runas`)
  - **Security 4625** (failed logons)
  - **Security 4720** (user account created)

## Detection Engineering (In Progress)
Created custom detection rules in Elastic Security:
- **Explicit Credential Use Detected (EID 4648)** — KQL: `winlog.channel:"Security" and event.code:"4648"`
- **Test – Sysmon Process Execution (EID 1)** — KQL: `winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:"1"`

> Note: Rules executed successfully, but alert visibility required additional tuning (time range, rule schedule/lookback, and Security Solution prerequisites).

## Key Learnings
- Lab setup is *not* plug-and-play: networking, bindings (0.0.0.0 vs 127.0.0.1), and service readiness can block ingestion/alerts.
- PowerShell script block logs (4104) won’t appear unless PowerShell logging is enabled — Sysmon EID 1 still captures the command line.
- Validating telemetry end-to-end (endpoint → beat → Elasticsearch → Kibana) is the first win before “cool attacks”.

## Next Steps
- Enable and validate more Windows audit categories (logon, object access, process tracking).
- Generate controlled attack telemetry from Kali to Windows (SMB auth attempts, share enumeration) and confirm visibility.
- Tune Elastic Security rules to reliably create alerts and build investigation timelines.

## Repo Map
- `lab-setup/` — architecture + network notes
- `detection/` — rules + queries
- `investigation/` — timeline + findings
- `lessons-learned.md` — what worked / what broke / fixes
