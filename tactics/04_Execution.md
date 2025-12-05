---
tags:
  - ATTACK/Execution
  - Surface/Network
  - Surface/File
  - Surface/Process
  - Telemetry/Sysmon
  - Telemetry/PowerShell
---
# Execution (TA0002)

Execution involves techniques that allow adversaries to run malicious code on local or remote systems. This often works in conjunction with other tactics, like exploring the network or stealing data. For example, an adversary might use a remote access tool to run a PowerShell script for system discovery.

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

- [Encoded or Obfuscated Command Lines](encoded_command_lines.md)
- [PowerShell Script Block Logging](powershell_script_block_logging.md)
- [Core Script Interpreter and LOLBin Execution](script_execution_interpreter.md)
- [Execution from Suspicious Locations](suspicious_location_executions.md)

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

