---
tags:
  - ATTACK/ResourceDevelopment
  - Sysmon
  - pfSense
  - Surface/File
  - Surface/Network
---

# Resource Development (TA0042)

Adversaries prepare infrastructure, tools, and capabilities prior to gaining access.  
Most Resource Development occurs **outside** the target environment, but some actions leave traces inside your lab (tool downloads, staging, packaging).

---

## Common Sub-Techniques

**T1588 – Obtain Capabilities**  
Payloads, malware, scanners, and post-exploitation tooling are downloaded or staged.

**T1608 – Stage Capabilities**  
Attackers place tools in locations where they can be executed later (Temp, AppData, Downloads).

**T1583 – Acquire Infrastructure**  
External services or hosts used for later access (rarely visible inside lab unless contacted).

---

## Expected Surfaces

**Network** – outbound connections retrieving tooling  
**File System** – staged tools, archives, payloads dropped onto disk  
**Process** – browsers, PowerShell, curl/wget used to download tools

---

## What to Look For

### Network Indicators
- Outbound connections to IPs/domains not part of the lab (tool retrieval)  
- File downloads via HTTP/HTTPS from unrecognized hosts  
- Repeated outbound requests to the same external IP

### File System Indicators
- New files appearing in:  
  - `Downloads`  
  - `AppData\Local\Temp`  
  - `Users\Public`  
- Archived tools (`.zip`, `.7z`, `.rar`)  
- Staged executables used later in the intrusion chain

### Behavioral Patterns
- PowerShell used to download files (Invoke-WebRequest / curl)  
- Tools with suspicious filenames suddenly appearing  
- File staging preceding Execution or Initial Access activity

---

## Starter Splunk Queries

### 1. External File Download (Sysmon Network Events)
```
index=sysmon EventCode=3 earliest=-1h
| search DestinationIp!="10.10.*"
| table _time host Image DestinationIp DestinationPort
```
Purpose: Detect outbound connections to non-lab IPs, often used to fetch tooling.

---

### 2. File Staging in Download/Temp Paths
```
index=sysmon EventCode=11 earliest=-1h
| search TargetFilename="*\Downloads\*" OR TargetFilename="*\Temp\*"
| table _time host Image TargetFilename User
```
Purpose: Identifies tool staging in common download locations.

---

### 3. Archive Extraction or Tool Packaging
```
index=sysmon EventCode=11 earliest=-1h
| search TargetFilename="*.zip" OR TargetFilename="*.7z" OR TargetFilename="*.rar"
| table _time host Image TargetFilename User
```
Purpose: Highlights compressed toolkits or payload packages extracted to disk.

---

### 4. Suspicious PowerShell Download Activity
```
index=powershell earliest=-1h
| search ScriptBlockText="*Invoke-WebRequest*" OR ScriptBlockText="*curl*" OR ScriptBlockText="*wget*"
| table _time host User ScriptBlockText
```
Purpose: Detects PowerShell-based download commands commonly used for staging.

---

## Enhancements

### Telemetry Notes
- Resource Development is mostly external; detection relies on **download and staging behavior**, not attacker infrastructure creation.  
- Ensure Sysmon EventCode 11 (file create) is enabled and forwarding correctly.

### Detection Engineering Tips
- Combine **file creation** + **process execution** to identify staging followed by execution.  
- Tag external IPs dynamically to distinguish lab vs non-lab traffic.  
- File writes to `Temp` often precede PowerShell or LOLBin execution.

---
