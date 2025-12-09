---
tags:
  - ATTACK/Collection
  - Surface/Network
  - Surface/File
  - Surface/Process
  - Telemetry/Sysmon
  - Telemetry/WindowsEvent
---
# Collection (TA0009)

Collection involves techniques adversaries use to gather information relevant to their goals. After collecting data, they may steal it or use it to learn more about the environment. Common targets include files, browsers, audio, video, and email, and methods often involve capturing screenshots, keystrokes, or other user activity.

---

## Common Sub-Techniques

**T1119 – Automated Collection**  
Scripts or tools that automatically gather system/user data (documents, browser data, configuration).

**T1560 – Archive Collected Data**  
Creation of ZIP/7z/RAR files for staging exfiltration.

**T1005 – Data from Local System**  
Copying data from local file systems (Documents, Desktop, Downloads, application folders).

---

## Expected Surfaces

**File System** – staging of data, archive creation, mass file activity  
**Process** – collection scripts, archiving utilities  
**Network** – may show prep-stage callbacks ahead of exfiltration

---

## What to Look For

### File System Indicators

- Archives created in:
  - %TEMP%
  - %APPDATA%
  - %USERPROFILE%
  - Shared or mapped drives
- Sudden appearance of large files or many files in a short timeframe
- Staging subdirectories populated with mixed file types (docs, CSVs, text files)

### Process Indicators

- Execution of:
  - 7z.exe, rar.exe, zip.exe, or similar archivers
  - PowerShell commands reading or copying many files
- Scripts that enumerate directories and write output into new locations

### Behavioral Patterns

- Enumerate → copy → compress → later exfil  
- Collection activity followed by C2 or external network connections  
- Data gathered from multiple user folders or shares into a single staging directory

---

## Starter Splunk Queries

- [Archive Creation Detected](archive_creation.md)
- [High-Volume File Writes by a Single Process](process_file_writes.md)
- [PowerShell-Based File Enumeration and Copy](powershell_file_enumeration.md)
- [Access to Common User Data Locations](access_user_data.md)

---

## Enhancements

### Telemetry Notes

- Collection often resembles normal user or backup activity; context is key.  
- On non-server endpoints, archive creation and bulk file access can be strong signals.

### Detection Engineering Tips

- Combine archive creation with recent directory enumeration to increase confidence.  
- Track processes that touch multiple user folders or map multiple shares.  
- Correlate Collection events with subsequent outbound traffic when building full-chain detections.

---
