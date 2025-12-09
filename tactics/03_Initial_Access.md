---
tags:
  - ATTACK/InitialAccess
  - Surface/Network
  - Surface/Process
  - Surface/Identity
  - Telemetry/Sysmon
  - Telemetry/Suricata
  - Telemetry/WindowsEvent
---
# Initial Access (TA0001)

Initial Access involves adversaries using various methods to enter a network, such as spearphishing or exploiting vulnerabilities in public-facing servers. Once inside, they may establish persistent access (e.g. valid accounts, remote services) or face limited access (e.g. changing passwords).

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

- [Office or Browser Triggering Script Execution](execution_following_download.md)
- [Suspicious Authentication Activity](ids_exploit_attempts.md)
- [Exploit Attempts via IDS](payload_script_execution.md)
- [Malicious File Download Followed by Execution](suspicious_authentication_activity.md)

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

