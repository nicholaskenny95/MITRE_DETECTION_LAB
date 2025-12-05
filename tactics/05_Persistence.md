---
tags:
  - ATTACK/Persistence
  - Sysmon
  - WindowsSecurity
  - Surface/Registry
  - Surface/Process
  - Surface/File
---

# Persistence (TA0003)

Persistence techniques allow adversaries to maintain access across reboots, credential changes, and system restarts.  
In your lab, persistence most commonly appears as **registry autoruns**, **startup folder modifications**, **malicious services**, or **scheduled tasks**.

---

## Common Sub-Techniques

**T1547 – Boot or Logon Autostart Execution**  
Registry Run keys, Startup folder items, Winlogon modifications.

**T1053 – Scheduled Task/Job**  
Creation of scheduled tasks for recurring execution.

**T1543 – Create or Modify System Process**  
Abusing Windows services or installing new ones pointing to attacker binaries.

---

## Expected Surfaces

**Registry** – Run keys, service configurations, policy changes  
**File System** – startup items, dropped binaries, modified executables  
**Process** – service creation, task scheduler invocation

---

## What to Look For

### Registry Indicators
- Writes to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`  
- Modifications under `RunOnce`, `Winlogon`, or `Image File Execution Options`  
- Creation of new services pointing to non-standard binaries  
- Changes to scheduled tasks via registry (less common)

### File System Indicators
- Files added to:
  - `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
  - `%PROGRAMDATA%`
  - `%TEMP%`
  - `%WINDIR%\System32` (rare, high risk)
- Newly written `.lnk`, `.ps1`, `.vbs`, or `.exe` in autorun paths

### Process Indicators
- Execution of `schtasks.exe`, `sc.exe`, `powershell.exe` configuring scheduled tasks or services  
- Service creation events  
- Command lines referencing autostart locations

### Behavioral Patterns
- File dropped → registry modified → restart triggered  
- Service installed and immediately started  
- Scheduled task created with suspicious XML or command

---

## Starter Splunk Queries

### 1. Registry Run Keys (Sysmon Registry Events)
```
index=sysmon EventCode=13 earliest=-1h
| search registry_key_path="*\Run*" OR registry_key_path="*\RunOnce*" 
| table _time host Image registry_key_path Details User
```
Purpose: Detects persistence through autorun registry keys.

---

### 2. Startup Folder Modifications (Sysmon File Events)
```
index=sysmon EventCode=11 earliest=-1h
| search TargetFilename="*\Startup\*" 
        OR TargetFilename="*AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup*"
| table _time host Image TargetFilename User
```
Purpose: Identifies files placed in user startup locations.

---

### 3. Service Creation (Windows Security Event)
```
index=windows EventCode=4697 earliest=-1h
| table _time host ServiceName ServiceFileName Account_Name
```
Purpose: Monitors for potential malicious service installs.

---

### 4. Scheduled Tasks Created (Windows Security Event)
```
index=windows EventCode=4698 earliest=-1h
| table _time host TaskName Author
```
Purpose: Detects new scheduled tasks created for persistence.

---

## Enhancements

### Telemetry Notes
- Sysmon EventCodes 12/13/14 provide detailed registry visibility; ensure they are enabled.  
- Scheduled task logging varies by Windows version; ensure EventCode 4698 is being forwarded.  
- Service creation event (4697) is high-signal, low-noise.

### Detection Engineering Tips
- Combine **file creation** with **registry modification** for high-confidence persistence detection.  
- Track new services and scheduled tasks where the binary path is user-writable.  
- Build allow-lists for legitimate startup items to reduce noise.

---

