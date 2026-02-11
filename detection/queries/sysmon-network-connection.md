## Detection: Suspicious Outbound Network Connection

**Data Source**
- Sysmon Event ID 3
- Winlogbeat → Elastic Security

**Detection Logic**
Detects non-browser processes initiating outbound connections on uncommon ports.

**Why it matters**
Adversaries often use high or uncommon ports for:
- Payload staging
- C2 beacons
- Data exfiltration

**Observed Activity**
- Source Host: Windows endpoint
- Process: powershell.exe
- Destination IP: 10.0.2.5
- Port: 8000
