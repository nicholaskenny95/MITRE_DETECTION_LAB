---
tags:
  - ATTACK/InitialAccess
  - Sysmon
  - Suricata
  - WindowsSecurity
  - Surface/Network
  - Surface/Process
  - Surface/Identity
---

# Initial Access (TA0001)

Initial Access covers techniques that allow adversaries to gain a foothold inside the environment.  
In a lab, this typically appears as **malicious document execution**, **remote authentication**, or **exploit traffic**.

---

## Common Sub-Techniques

**T1566 – Phishing**  
User opens a malicious file or link leading to execution.

**T1190 – Exploit Public-Facing Application**  
Exploit attempts coming from external sources.

**T1133 – External Remote Services**  
Authentication to RDP, SMB, VPN, or WinRM using stolen credentials.

---

## Expected Surfaces

**Process** – user execution, Office spawning scripts  
**Network** – inbound exploit attempts, external downloads  
**Identity** – unusual or first-time logon events

---

## What to Look For

### Process Indicators
- `winword.exe`, `excel.exe`, or browser processes spawning PowerShell or CMD  
- Office macros executing: `powershell.exe`, `wscript.exe`, `mshta.exe`  
- Script interpreters invoked with encoded or obfuscated commands

### Network Indicators
- Suricata alerts for exploitation attempts  
- Inbound connections from non-lab IPs  
- File downloads that immediately trigger process execution

### Identity Indicators
- Successful logons from unexpected IPs  
- High-volume failed logon attempts  
- LogonType 10 (RDP) or LogonType 3 (network logon) from unknown sources

### Behavioral Patterns
- Document opens → script execution → network callback  
- Failed logons followed by a successful one  
- User-triggered processes spawning LOLBins

---

## Starter Splunk Queries

### 1. Office or Browser Triggering Script Execution
```
index=sysmon EventCode=1 earliest=-1h
| search ParentImage="*winword.exe*" OR ParentImage="*excel.exe*" 
        OR ParentImage="*outlook.exe*" OR ParentImage="*chrome.exe*" 
        OR ParentImage="*firefox.exe*"
| table _time host ParentImage Image CommandLine User
```
Purpose: Detects phishing payload execution via parent/child anomalies.

---

### 2. Suspicious Authentication Activity
```
index=windows EventCode=4624 earliest=-1h
| table _time host Account_Name Logon_Type IpAddress
```
Purpose: Logs successful logons which may indicate stolen credential use.

---

### 3. Exploit Attempts via IDS (Suricata)
```
index=ids earliest=-1h
| search signature="*exploit*" OR signature="*shellcode*" OR signature="*malicious*"
| table _time src_ip dest_ip dest_port signature
```
Purpose: Identifies network-based exploit attempts against lab systems.

---

### 4. Malicious File Download Followed by Execution
```
index=sysmon EventCode=3 earliest=-1h
| search DestinationIp!="10.10.*"
| join host [_internal]
```
(This placeholder ready for further correlation)

Purpose: Highlights external downloads that commonly precede execution.

---

## Enhancements

### Telemetry Notes
- Office → PowerShell is one of the strongest initial access indicators.  
- IDS may miss low-and-slow exploit attempts; correlate with process activity.  
- External remote logons should be rare or nonexistent in a closed lab.

### Detection Engineering Tips
- Correlate **document open events** with **Sysmon 1 execution events**.  
- Build allow-lists for known legitimate remote admin activity.  
- Track first-seen IPs for authentication activity.

---

