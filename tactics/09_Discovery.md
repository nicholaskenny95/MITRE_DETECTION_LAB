---
tags:
  - ATTACK/Discovery
  - Sysmon
  - WindowsSecurity
  - Surface/Process
  - Surface/Network
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

### 1. Classic Windows Discovery Commands (Sysmon Process Creation)
```
index=sysmon EventCode=1 earliest=-1h
| search Image="*\net.exe" OR Image="*\nltest.exe" OR Image="*\ipconfig.exe" 
        OR Image="*\wmic.exe" OR Image="*\whoami.exe"
| table _time host Image ParentImage CommandLine User
```
Purpose: Detects most built-in Windows discovery commands.

---

### 2. PowerShell Discovery Activity
```
index=powershell earliest=-1h
| search ScriptBlockText="*Get-AD*" OR ScriptBlockText="*Get-WmiObject*" 
        OR ScriptBlockText="*Get-NetIPAddress*" OR ScriptBlockText="*Get-Process*"
| table _time host User ScriptBlockText
```
Purpose: Identifies PowerShell-based domain and system enumeration.

---

### 3. Internal Host Enumeration (Sysmon Network)
```
index=sysmon EventCode=3 earliest=-1h
| stats dc(DestinationIp) as unique_targets by host, Image
| where unique_targets > 5
```
Purpose: Captures processes querying multiple internal hosts.

---

### 4. Domain Controller and Trust Enumeration (Sysmon Process Creation)
```
index=sysmon EventCode=1 earliest=-1h
| search CommandLine="*nltest*" OR CommandLine="*/dclist*" OR CommandLine="*/domain_trusts*"
| table _time host Image CommandLine User
```
Purpose: Detects enumeration of domain controllers or domain trusts.

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

