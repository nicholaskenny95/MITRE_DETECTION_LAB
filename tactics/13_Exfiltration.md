---
tags:
  - ATTACK/Exfiltration
  - Surface/Network
  - Sysmon
  - Suricata
  - pfSense
  - Surface/Process
  - Surface/File
---

# Exfiltration (TA0010)

Exfiltration techniques involve adversaries removing collected data from the environment.  
In your lab, this typically appears as **outbound file transfers**, **HTTP/HTTPS uploads**, **DNS tunneling**, **encrypted exfil**, or **copying data to remote shares**.

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

### 1. Large Outbound Transfers (Sysmon Network Events)
```
index=sysmon EventCode=3 earliest=-1h
| stats count by DestinationIp DestinationPort Image host
| sort - count
```

### 2. HTTP/HTTPS POST Uploads (Suricata)
```
index=ids earliest=-1h
| search signature="*POST*" OR signature="*UPLOAD*" OR signature="*data exfil*"
| table _time src_ip dest_ip dest_port signature
```

### 3. PowerShell-Based Upload Commands
```
index=powershell earliest=-1h
| search ScriptBlockText="*Invoke-WebRequest*" AND ScriptBlockText="*POST*"
       OR ScriptBlockText="*Invoke-RestMethod*"
| table _time host User ScriptBlockText
```

### 4. Data Transfer to External IPs
```
index=sysmon EventCode=3 earliest=-1h
| search DestinationIp!="10.10.*"
| table _time host Image DestinationIp DestinationPort
```

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
