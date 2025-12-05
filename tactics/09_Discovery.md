---
tags:
  - ATTACK/Discovery
  - Surface/Process
  - Surface/Network
  - Telemetry/Sysmon
  - Telemetry/WindowsEvent
---

# Discovery (TA0007)

Discovery techniques help adversaries learn about the environment after gaining a foothold.  
In your lab, this most often appears as **Windows built-in enumeration commands**, **PowerShell discovery**, and **network probing**.

---

## Common Sub-Techniques

**T1087 – Account Discovery**  
Enumerating domain users, groups, or local accounts.

**T1018 – Remote System Discovery**  
Identifying computers, servers, or network assets.

**T1049 – System Network Connections Discovery**  
Listing network connections, ports, and sessions on the endpoint.

---

## Expected Surfaces

**Process** – enumeration commands, PowerShell queries  
**Network** – internal scans or targeted discovery attempts  
**Identity** – occasional group enumeration tools (less common)

---

## What to Look For

### Process Indicators
- Execution of discovery tools:
  - `net.exe user`, `net.exe group`, `net.exe view`
  - `nltest.exe /dclist`, `/domain_trusts`
  - `ipconfig.exe`, `whoami.exe`, `quser.exe`, `tasklist.exe`
  - `wmic.exe` with system or user queries
- PowerShell discovery commands:
  - `Get-ADUser`, `Get-ADComputer`
  - `Get-WmiObject`, `Get-NetIPAddress`
- Batch enumeration: multiple enumeration commands in rapid succession

### Network Indicators
- Lookups and scans targeting internal hosts/domains  
- SMB or RPC enumeration  
- ICMP sweeps or repeated DNS queries from unusual hosts

### Behavioral Patterns
- Reconnaissance → multiple discovery commands → credential or lateral movement attempt  
- Enumeration from non-admin accounts or normal user workstations 
- Discovery run from odd parent processes (e.g., Office, browser)

---

## Starter Splunk Queries

- [Classic Windows Discovery Commands](../queries/starter/windows_discovery_commands.md)
- [PowerShell Discovery Activity](../queries/starter/powershell_discovery_activity.md)
- [Internal Host Enumeration](../queries/starter/internal_host_enumeration.md)
- [Domain Controller and Trust Enumeration](../queries/starter/domain_controller_enumeration.md)

---

## Enhancements

### Telemetry Notes
- Sysmon EventCode 1 is the most important source for Discovery—almost all enumeration tools trigger it.  
- PowerShell logs (4104) provide full command visibility for discovery-heavy techniques.

### Detection Engineering Tips
- Combine multiple discovery events over short time windows to reduce noise.  
- Baseline administrative hosts to avoid false positives from legitimate IT operations.  
- Correlate Discovery with follow-on behaviors (Credential Access, Lateral Movement).

---

