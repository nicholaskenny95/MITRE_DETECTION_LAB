---
tags:
  - ATTACK/DefenseEvasion
  - Surface/File
  - Surface/Process
  - Surface/Registry
  - Surface/Network
  - Telemetry/Sysmon
  - Telemetry/WindowsEvent
  - Telemetry/PowerShell
---

# Defense Evasion (TA0005)

Defense Evasion techniques allow adversaries to conceal their activity, disable security controls, remove evidence, or blend into normal system behavior.  
In this lab, Defense Evasion is most visible through **PowerShell misuse**, **registry tampering**, **log clearing**, **LOLBin abuse**, and **security control modification**.

---

## Common Sub-Techniques

**T1562 – Impair Defenses**  
Disabling or modifying Windows Defender, firewall, Sysmon, or logging components.

**T1140 – Deobfuscate/Decode Files or Information**  
Encoded or obfuscated payloads executed via PowerShell, CMD, or LOLBins.

**T1070 – Indicator Removal**  
Clearing event logs, deleting artifacts, overwriting or renaming files.

---

## Expected Surfaces

**Process** – obfuscated scripts, LOLBins, security tool tampering  
**Registry** – Defender, firewall, and logging configuration changes  
**File System** – tampered logs, modified executables or scripts  
**Network** – abnormal traffic after evasion (e.g., C2 connection begins)

---

## What to Look For

### Process Indicators
- PowerShell with:
  - `-enc` or Base64 commands  
  - AMSI bypass attempts  
  - ScriptBlock modifications  
- LOLBins used for evasion:
  - `reg.exe`  
  - `rundll32.exe`  
  - `wmic.exe`  
  - `mshta.exe`  
- Event log clearing tools:  
  `wevtutil.exe`, `Clear-EventLog`, `logman.exe`

### Registry Indicators
- Defender tampering:
  - `HKLM\Software\Microsoft\Windows Defender\*`  
- Logging disabled:
  - `HKLM\Software\Policies\Microsoft\Windows\EventLog\*`  
- AMSI tampering or disabling script scanning

### File System Indicators
- Deleted or overwritten log files  
- Modified Sysmon config (if centrally managed)  
- Newly dropped DLLs for LOLBin hijacking

### Behavioral Patterns
- Obfuscated command → registry modification → reduced visibility  
- Log clearing immediately before or after malicious execution  
- Tampering followed by credential access or C2 communication

---

## Starter Splunk Queries

- [Obfuscated or Encoded Execution](../queries/starter/encoded_execution_obfuscation.md)
- [PowerShell-Based Defense Evasion](../queries/starter/powershell_defense_evasion.md)
- [Log Clearing and Evidence Removal](../queries/starter/evidence_log_removal.md)
- [Registry Modification for Evasion](../queries/starter/evasion_registry_modification.md)

---

## Enhancements

### Telemetry Notes
- PowerShell Script Block Logging (EventCode 4104) is crucial for detecting obfuscation attempts.  
- Sysmon EventCode 13 provides deep insight into registry tampering—ensure it's enabled.  
- Many evasion techniques are “lot of noise when security logs are missing”—absence of logs is itself a signal.

### Detection Engineering Tips
- Look for **timing correlation**: evasion often occurs directly before credential access or lateral movement.  
- Build allow-lists for legitimate administrative Defender modifications.  
- Use encoded-command detection as part of broader anomaly logic to reduce false positives.

---

