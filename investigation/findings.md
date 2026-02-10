# Findings (Case Brief)

## Signals observed
- **Security 4648**: explicit credentials used (runas-style behavior)
- **Security 4625**: repeated failed logons (bad password attempts)
- **Security 4720**: local user creation events (test accounts)
- **Sysmon 1**: process creation including PowerShell (encoded command lines)
- **Sysmon 3 / 22**: network connections + DNS activity (baseline + testing)

## Notes
Some attacker-originated activity from Kali did not show as expected. Likely causes include:
- Windows services not exposed/blocked (firewall, sharing settings, service state)
- Using the wrong protocol/tool for a “real” Windows auth event
- Telemetry present but missed due to time range / data view / filters
