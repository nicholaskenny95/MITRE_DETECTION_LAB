---
tags:
  - ATTACK/CredentialAccess
  - Surface/Process
  - Surface/Registry
  - Surface/File
  - Surface/Identity
  - Telemetry/Sysmon
  - Telemetry/WindowsEvent
---

# Credential Access (TA0006)

Credential Access techniques allow adversaries to steal, dump, or harvest authentication material.  
In your lab, this frequently appears as **LSASS access**, **hash dumping**, **SAM hive theft**, **credential extraction tools**, or **network-based credential misuse**.

---

## Common Sub-Techniques

**T1003 – OS Credential Dumping**  
Accessing `lsass.exe`, dumping process memory, or extracting SAM/SYSTEM/SECURITY hives.

**T1555 – Credentials from Password Stores**  
Targeting browser credential stores, DPAPI, or saved credential files.

**T1110 – Brute Force**  
Password spraying or repeated authentication attempts.

---

## Expected Surfaces

**Process** – access to LSASS, mimikatz-like behavior, dumping tools  
**Registry** – hive access, SAM/SYSTEM reads  
**File System** – dump files (`.dmp`), hive exports, credential artifacts  
**Identity** – failed logons, password spray indicators

---

## What to Look For

### Process Indicators
- `lsass.exe` accessed by unexpected processes  
- Tools such as:
  - `procdump.exe`
  - `mimikatz.exe`
  - `rundll32.exe` with unusual parameters  
- Processes requesting dangerous access rights (e.g., `0x1FFFFF`)

### Registry Indicators
- Reads of:
  - `HKLM\SAM`
  - `HKLM\SYSTEM`
  - `HKLM\SECURITY`  
- Registry hive copying or exporting

### File System Indicators
- `.dmp` files created in:
  - `%TEMP%`
  - `%WINDIR%\Temp`
  - User directories  
- `SAM`, `SYSTEM`, or `SECURITY` hive backups

### Identity Indicators
- Repeated 4625 failed logons (password spraying)
- Legitimate accounts authenticating from unusual hosts
- Account lockouts or multiple authentication attempts

### Behavioral Patterns
- LSASS dump → credential theft → lateral movement  
- Hive exports followed by decoding attempts  
- Failed logons → successful logon from same user

---

## Starter Splunk Queries

- [LSASS Access Attempts](../queries/starter/lsass_access_attempts.md)
- [Credential Dump Tools Executed](../queries/starter/credential_dump_executed.md)
- [Registry Hive Access](../queries/starter/registry_hive_access.md)
- [Failed Logon Burst](../queries/starter/failed_logon_burst.md)

---

## Enhancements

### Telemetry Notes
- Sysmon EventCode 10 is essential for detecting LSASS access—confirm it is enabled in your configuration.  
- Many credential access tools rename themselves; rely on behavior and access patterns, not filenames.

### Detection Engineering Tips
- Combine **EventCode 10** with **EventCode 1** for stronger detection (who accessed LSASS + how). 
- Correlate failed logons with successful ones to identify credential stuffing.  
- Alert on LSASS access attempts by processes not in a known-good allow-list (e.g., legitimate AV or EDR tools).

---
