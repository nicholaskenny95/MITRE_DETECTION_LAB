---
tags:
  - ATTACK/ResourceDevelopment
  - Surface/File
  - Surface/Network
  - Telemetry/Sysmon
  - Telemetry/pfSense
---
# Resource Development (TA0042)

Resource Development is when adversaries create, buy, or steal the tools and infrastructure they need for their operations. This can include things like domains, accounts, or capabilities, which they later use for other stages of an attack, such as command and control, phishing for initial access, or using stolen certificates to evade defenses.

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

- [File Staging in Download/Temp Paths](../queries/starter/file_staging_paths.md)
- [Archive Extraction or Tool Packaging](../queries/starter/suspicious_powershell_download.md)
- [Suspicious PowerShell Download Activity](../queries/starter/external_file_download.md)
- [External File Download](../queries/starter/external_file_download.md)

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
