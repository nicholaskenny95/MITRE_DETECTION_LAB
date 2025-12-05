---
tags:
  - ATTACK/PrivilegeEscalation
  - Sysmon
  - WindowsSecurity
  - Surface/Process
  - Surface/Registry
  - Surface/File
  - Surface/Identity
---

# Privilege Escalation (TA0004)

Privilege Escalation techniques allow adversaries to gain higher-level permissions, often enabling full system compromise.  
In your lab, this commonly appears through **token manipulation**, **misconfigured services**, **UAC bypass**, and **credentialed execution**.

---

## Common Sub-Techniques

**T1055 – Process Injection**  
Injecting into privileged processes to inherit permissions.

**T1548 – Abuse Elevation Control Mechanisms**  
UAC bypass, token manipulation, or misuse of “runas” functionality.

**T1543 – Create or Modify System Process**  
Leveraging services or scheduled tasks configured with elevated permissions.

---

## Expected Surfaces

**Process** – elevated processes, unusual parent/child chains  
**Registry** – modified services or configuration keys enabling escalation  
**File System** – replacement of service executables or DLL hijacking  
**Identity** – logons with elevated privileges or special tokens

---

## What to Look For

### Process Indicators
- PowerShell or CMD running with elevated tokens unexpectedly  
- Low-privilege processes spawning high-privilege children  
- `runas.exe`, `psexec.exe`, or UAC bypass tools appearing  
- Mismatched integrity levels (medium → high transitions)

### Registry Indicators
- Changes to service configuration paths (`ImagePath`)  
- Modifications under:
  - `HKLM\SYSTEM\CurrentControlSet\Services\*`
  - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

### Identity Indicators
- EventCode **4672** (special privileges assigned)  
- Administrative logons from non-admin endpoints  
- Privileged logons occurring shortly before suspicious process activity

### Behavioral Patterns
- Registry/service modification → elevated process starts  
- Process injection followed by unexpected network traffic  
- Rapid privilege change followed by credential access or lateral movement

---

## Starter Splunk Queries

### 1. High-Privilege Token Assignment (Windows Security)
```
index=windows EventCode=4672 earliest=-1h
| table _time host SubjectUserName Privileges
```
Purpose: Detects users receiving elevated privileges (high-fidelity escalation signal).

---

### 2. Suspicious Elevated Process Execution
```
index=sysmon EventCode=1 earliest=-1h
| search IntegrityLevel="High" OR IntegrityLevel="System"
| table _time host Image ParentImage CommandLine User IntegrityLevel
```
Purpose: Highlights unexpectedly elevated processes.

---

### 3. Service Configuration Modification (Sysmon Registry)
```
index=sysmon EventCode=13 earliest=-1h
| search registry_key_path="*\Services\*" AND Details="*ImagePath*"
| table _time host Image registry_key_path Details User
```
Purpose: Detects service misconfiguration attempts used for escalation.

---

### 4. Execution of Known Escalation Utilities
```
index=sysmon EventCode=1 earliest=-1h
| search Image="*psexec.exe*" OR Image="*runas.exe*" OR CommandLine="*bypass*" 
| table _time host Image ParentImage CommandLine User
```
Purpose: Identifies common tools and methods used to elevate privileges.

---

## Enhancements

### Telemetry Notes
- EventCode **4672** is reliable for privilege assignment detection.  
- Sysmon does not natively log token manipulation—look for indirect signals (parent/child chain anomalies, integrity jumps).  
- Service modification detection relies on EventCodes 12/13; ensure registry monitoring is active.

### Detection Engineering Tips
- Pair elevated process creation with preceding registry modifications for high-confidence escalation detection.  
- Track which binaries normally run elevated and alert on deviations.  
- Watch for privilege escalation immediately followed by credential access or lateral movement.

---

