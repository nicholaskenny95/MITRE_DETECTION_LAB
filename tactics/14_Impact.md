---
tags:
  - Surface/Process
  - Surface/File
  - Surface/Registry
  - Sysmon
  - WindowsSecurity
  - ATTACK/Impact
---

# Impact (TA0040)

Impact techniques are used by adversaries to disrupt availability, compromise integrity, or destroy data.  
In your lab environment, Impact typically appears as **data destruction**, **service interruption**, **inhibiting recovery**, or **ransomware-style encryption behavior**.

---

## Common Sub-Techniques

**T1485 – Data Destruction**  
Deletion or corruption of files, often via scripts or destructive tools.

**T1490 – Inhibit System Recovery**  
Deleting shadow copies, disabling backups, altering recovery configurations.

**T1486 – Data Encryption for Impact**  
Ransomware-style encryption of user files, often in mass file write operations.

---

## Expected Surfaces

**File System** – mass deletions, file rewrites, encryption artifacts  
**Process** – destructive utilities, PowerShell wiping commands, vssadmin usage  
**Registry** – modifications disabling recovery features  
**Identity** – seldom relevant, except impersonation of admin users

---

## What to Look For

### File System Indicators
- Mass deletion (`del`, `Remove-Item`, wiping scripts)  
- Rapid creation of encrypted file extensions  
- Overwriting or corrupting file contents  
- Deletion of:
  - Shadow copies  
  - Backup repositories  
  - System restore points  

### Process Indicators
- Usage of:
  - `vssadmin.exe delete shadows`
  - `wmic shadowcopy delete`
  - `cipher.exe /w`
  - `format.exe`
- Ransomware-like behaviors:
  - High-volume file writes  
  - Short-lived processes rewriting files  
  - Tools executing from temp directories  

### Registry Indicators
- Disabling Windows recovery or backup policies  
- Changing boot configurations  
- Modifying system restore service settings

### Behavioral Patterns
- Backup deletion → rapid file encryption → ransom note creation  
- Destructive commands from unusual parent processes  
- Encryption preceded by privilege escalation

---

## Starter Splunk Queries

### 1. Backup/Shadow Copy Deletion
```
index=sysmon EventCode=1 earliest=-1h
| search CommandLine="*vssadmin*" AND CommandLine="*delete*"
        OR CommandLine="*wmic shadowcopy*"
| table _time host Image ParentImage CommandLine User
```

### 2. High-Volume File Modifications (Encryption/Deletion)
```
index=sysmon EventCode=11 earliest=-1h
| stats count by host Image User
| where count > 100
| sort - count
```

### 3. Destructive Utilities Execution
```
index=sysmon EventCode=1 earliest=-1h
| search Image="*cipher.exe*" OR Image="*format.exe*" OR CommandLine="*Remove-Item*"
| table _time host Image ParentImage CommandLine User
```

### 4. Ransomware-Like File Extensions
```
index=sysmon EventCode=11 earliest=-1h
| search TargetFilename="*.locked" OR TargetFilename="*.encrypted" OR TargetFilename="*.enc"
| table _time host Image TargetFilename User
```

---

## Enhancements

### Telemetry Notes
- Ransomware often uses legitimate Windows tools before encryption (vssadmin, wmic).  
- File write volume is one of the strongest indicators of destructive activity.

### Detection Engineering Tips
- Correlate backup deletion with subsequent mass file writes.  
- Monitor for encryption extensions not normally seen in the environment.  
- Build prevention/detection rules around mass file access patterns.

---

