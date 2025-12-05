---
tags:
  - Surface/Process
  - Surface/File
  - Surface/Registry
  - ATTACK/Impact
  - Telemetry/Sysmon
  - Telemetry/WindowsEvent
---
# Impact (TA0040)

Impact involves techniques adversaries use to disrupt systems, compromise data integrity, or interfere with business operations. This can include destroying or tampering with data, or subtly altering business processes to benefit the adversary’s goals. These actions may serve as part of their broader objectives or provide cover for other breaches, like stealing confidential information.

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

- [Backup/Shadow Copy Deletion](../queries/starter/backup_copy_deletion.md)
- [High-Volume File Modifications](../queries/starter/large_file_modifications.md)
- [Destructive Utilities Execution](../queries/starter/destructive_utilities_execution.md)
- [Ransomware-Like File Extensions](../queries/starter/ransomware_file_extensions.md)

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

