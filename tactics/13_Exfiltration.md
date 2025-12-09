---
tags:
  - ATTACK/Exfiltration
  - Surface/Network
  - Surface/Process
  - Surface/File
  - Telemetry/Sysmon
  - Telemetry/Suricata
  - Telemetry/pfSense
---
# Exfiltration (TA0010)

Exfiltration involves techniques adversaries use to steal data from a network. After collecting the data, they often package it using compression or encryption to avoid detection. Data is typically transferred over the command and control channel or another method, sometimes with size limits to evade monitoring.

---

## Common Sub-Techniques

**T1041 – Exfiltration Over C2 Channel**  
Sending staged data through an existing command-and-control channel.

**T1048 – Exfiltration Over Alternative Protocol**  
Using FTP, SMB, or custom protocols for file transfer.

**T1567 – Exfiltration Over Web Services**  
Uploading data to cloud services or attacker-controlled web servers.

---

## Expected Surfaces

**Network** – primary signal (upload traffic, unusual outbound ports)  
**File System** – data staged before transfer (archives, dumps)  
**Process** – tools or scripts performing uploads or copy operations

---

## What to Look For

### Network Indicators

- Large outbound data transfers  
- Upload behavior via:
  - HTTP/HTTPS POST  
  - FTP, SMB, or WebDAV  
  - DNS tunneling patterns  
- Outbound connections to unknown/non-lab IPs  
- Suricata alerts indicating data exfil or tunneling

### File System Indicators

- Recently created archives (`.zip`, `.7z`, `.rar`) followed by outbound connections  
- Temporary files used for staging large datasets  
- Collection directories emptied immediately after network activity

### Process Indicators

- PowerShell upload scripts:
  - `Invoke-WebRequest -Method POST`
  - `Invoke-RestMethod`
- Command-line tools like:
  - `curl.exe`, `bitsadmin.exe`, `certutil.exe`  
- FTP/SMB transfer utilities  
- Scripts executing just before network transfer

### Behavioral Patterns

- File staging → compress → upload  
- POST requests or bursts of encrypted traffic from endpoints that rarely communicate externally  
- Data exfil occurring shortly after collection activity

---

## Starter Splunk Queries

- [Large Outbound Transfers](large_outbound_transfers.md)
- [HTTP/HTTPS POST Uploads](http_post_uploads.md)
- [PowerShell-Based Upload Commands](powershell_upload_commands.md)
- [Data Transfer to External IPs](external_data_transfer.md)

---

## Enhancements

### Telemetry Notes

- Many exfil methods use HTTPS, making content invisible—behavior and timing matter most.  
- DNS tunneling requires IDS signatures or entropy-based detection.

### Detection Engineering Tips

- Correlate archive creation → outbound network events.  
- Flag POST traffic from endpoints that rarely upload data.  
- Build allowlists for legitimate external services to reduce false positives.

---
