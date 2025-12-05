---
tags:
  - ATTACK/CredentialAccess
  - Sysmon
  - WindowsSecurity
  - Surface/Process
  - Surface/Registry
  - Surface/File
  - Surface/Identity
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

### 1. LSASS Access Attempts (Sysmon EventCode 10)
```
index=sysmon EventCode=10 earliest=-1h
| search TargetImage="*lsass.exe*"
| table _time host SourceImage TargetImage GrantedAccess
```
Purpose: Detects attempts to access LSASS memory (high-fidelity indicator of dumping).

---

### 2. Credential Dump Tools Executed
```
index=sysmon EventCode=1 earliest=-1h
| search Image="*procdump*" OR Image="*mimikatz*" OR CommandLine="*lsass*"
| table _time host Image ParentImage CommandLine User
```
Purpose: Identifies tools commonly used for credential theft.

---

### 3. Registry Hive Access
```
index=sysmon EventCode=13 earliest=-1h
| search registry_key_path="*\SAM" OR registry_key_path="*\SYSTEM" OR registry_key_path="*\SECURITY"
| table _time host Image registry_key_path Details User
```
Purpose: Detects attempts to read or export credential-related registry hives.

---

### 4. Failed Logon Burst (Brute Force / Spray)
```
index=windows EventCode=4625 earliest=-1h
| stats count by Account_Name IpAddress
| where count > 5
| sort - count
```
Purpose: Identifies repeated authentication failures indicative of password spray activity.

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
