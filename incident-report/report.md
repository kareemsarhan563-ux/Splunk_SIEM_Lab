# Incident Report: SMB Brute Force & Post-Exploitation Recon

## 1. Executive Summary
On November 15, 2026, the Splunk SIEM generated a High severity alert for an SMB Brute Force attack. The attacker, originating from a Kali Linux machine (192.168.1.129), successfully compromised the Windows 10 endpoint (192.168.1.128) by obtaining valid credentials via a brute-force attack. Subsequent analysis revealed that the attacker executed post-exploitation discovery commands (whoami, ipconfig) to map the environment. The incident was triaged, the host was isolated, and the compromised account was secured.

## 2. Detection Details
- Alert Name: Brute Force Detected
- Detection Logic: The alert triggers when Windows Security EventCode 4625 exceeds 5 failed attempts from a single source IP within a 5-minute window. The detection was tuned to exclude SYSTEM and machine accounts to minimize false positives.
- Data Sources: Windows Security Logs (EventCode 4625), Sysmon (EventCode 1).

## 3. Timeline of Events
- 18:34 - Attacker initiated an automated Hydra brute-force attack against SMB.
- 18:34 - SIEM triggered a High severity alert for multiple failed logins from 192.168.1.129.
- 18:34 - Attacker successfully authenticated using the compromised Administrator credentials.
- 20:26 - Attacker executed Discovery commands (whoami) on the target endpoint.
- 20:40 - Sysmon detected and logged the execution of ipconfig, which was ingested by Splunk.

## 4. Indicators of Compromise (IOCs)

| Type | Value | Description |
| :--- | :--- | :--- |
| IPv4 | 192.168.1.129 | Attacker Source IP (Kali Linux) |
| Account | Administrator | Compromised Account |
| Tool | THC-Hydra | Brute Force Tool (Detected via event rate) |
| Command | whoami, ipconfig | Post-exploitation Discovery Commands |

## 5. MITRE ATT&CK Mapping
- Credential Access: T1110.001 (Brute Force: Password Guessing)
- Discovery: T1033 (System Owner/User Discovery)
- Discovery: T1016 (System Network Configuration Discovery)

## 6. Response & Containment Actions
- Host Isolation: The affected Windows 10 endpoint was immediately isolated from the network.
- Account Security: The compromised Administrator account was disabled, and a forced password reset was enforced.
- Network Defense: The attacker IP (192.168.1.129) was blocked at the perimeter firewall.
- Escalation: The incident was escalated to the L2/IR team for further forensic analysis.