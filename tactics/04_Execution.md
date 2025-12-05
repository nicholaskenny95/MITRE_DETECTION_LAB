---
tags:
  - ATTACK/Execution
  - Sysmon
  - PowerShell
  - Surface/Network
  - Surface/File
  - Surface/Process
---

# Execution (TA0002)

Execution covers techniques that run adversary-controlled code on a system.  
In this lab, this primarily appears as **script interpreters**, **LOLBin abuse**, and **malicious command lines** on Windows endpoints.

---

## Common Sub-Techniques

**T1059 – Command and Scripting Interpreter**  
Abuse of PowerShell, CMD, wscript, cscript, mshta, and similar engines.

**T1106 – Native API**  
Indirectly observable when wrapped by processes calling APIs to execute code.

**T1204 – User Execution**  
User-initiated execution of malicious content, often via documents or downloads.

---

## Expected Surfaces

**Process** – primary signal (new processes, parents, command lines)  
**File System** – secondary when scripts or binaries are written before execution  
**Network** – sometimes used immediately after execution for C2 or download

---

## What to Look For

### Process Indicators

- `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`  
- Long or obfuscated command lines (Base64, `-enc`, compressed content)  
- Unexpected parents (Office apps, browsers, script hosts spawning other tools)  
- Execution from temporary or user-writable directories

### File System Indicators

- Newly written `.ps1`, `.vbs`, `.js`, `.bat`, or `.exe` files followed quickly by execution  
- Scripts in `%TEMP%`, `%APPDATA%`, or `Downloads` that do not match trusted software

### Behavioral Patterns

- User action → script execution → network callback  
- PowerShell quickly spawning additional processes  
- LOLBins invoked with URLs, encoded payloads, or DLL paths

---

## Starter Splunk Queries

### 1. Core Script Interpreter and LOLBin Execution
```
index=sysmon EventCode=1 earliest=-30m
| search Image="*powershell.exe*" OR Image="*cmd.exe*" OR Image="*wscript.exe*" 
        OR Image="*cscript.exe*" OR Image="*mshta.exe*" OR Image="*rundll32.exe*"
| table _time host Image ParentImage CommandLine User
```
Purpose: Shows the main execution engines often abused by attackers.

---

### 2. PowerShell Script Block Logging (If Enabled)
```
index=powershell EventCode=4104 earliest=-1h
| table _time host User ScriptBlockText
```
Purpose: Reveals the actual PowerShell content, including malicious logic, even when obfuscated on the command line.

---

### 3. Encoded or Obfuscated Command Lines
```
index=sysmon EventCode=1 earliest=-1h
| search CommandLine="*-enc*" OR CommandLine="*EncodedCommand*" OR CommandLine="*Base64*"
| table _time host Image ParentImage CommandLine User
```
Purpose: Targets suspicious use of encoded payloads with PowerShell or CMD.

---

### 4. Execution from Suspicious Locations
```
index=sysmon EventCode=1 earliest=-1h
| search Image="*\Temp\*" OR Image="*\AppData\*" OR Image="*\Downloads\*"
| table _time host Image ParentImage CommandLine User
```
Purpose: Identifies binaries or scripts launching from common attacker staging paths.

---

## Enhancements

### Telemetry Notes

- Sysmon EventCode 1 (process creation) is critical for execution visibility; ensure it is configured and forwarded from all hosts.  
- PowerShell Script Block Logging (4104) greatly improves detection and investigation capability for T1059.  

### Detection Engineering Tips

- Combine **process parent/child relationships** with **command-line filters** to reduce noise.  
- Build known-good baselines for administrative script activity, then alert on deviations.  
- Link execution events to subsequent **network connections** (Sysmon 3) for C2 detection.

---

