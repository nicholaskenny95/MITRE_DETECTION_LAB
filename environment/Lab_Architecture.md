---
tags:
---

# Lab Environment Overview  
Consistent Reference for All MITRE ATT&CK Simulations

This document provides a standardized reference for the virtual lab environment used for all MITRE ATT&CK simulations executed with Atomic Red Team and analyzed using Splunk.  
It applies to all technique-specific lab reports to avoid repeating the same environment details.

---

# 1. Network Layout

The lab is segmented into three isolated networks, routed and filtered by pfSense:

1. **LAN** – Kali Linux (adversary simulation)  
2. **AD_LAB** – Windows Server Domain Controller + two Windows 10 clients  
3. **SECURITY** – Splunk Enterprise SIEM

Each network segment is isolated, with pfSense enforcing routing rules, segmentation, and forwarding IDS/syslog telemetry.

---

# 2. Systems Overview

## 2.1 Kali Linux (Attacker)
- **OS:** Debian-based Kali Linux  
- **Purpose:** Execute Atomic Red Team tests and simulate adversary behavior  
- **Tools Installed:**
  - Atomic Red Team  
  - PowerShell Core  
  - OpenSSH client

---

## 2.2 Active Directory Lab

### Domain Controller (DC1)
- **OS:** Windows Server 2019  
- **Hostname:** `DC1`  
- **Services:**
  - Active Directory Domain Services  
  - DNS  
  - DHCP  

### Windows 10 Clients
- **OS:** Windows 10 Enterprise  
- **Hostnames:** `WIN10-VM1`, `WIN10-VM2`  
- **State:** Domain joined  
- **Purpose:** Primary targets for technique execution  

---

## 2.3 Splunk Server (SIEM)
- **OS:** Ubuntu (64-bit)
- **Purpose:**
  - Receive Windows telemetry via Universal Forwarders  
  - Ingest Suricata and pfSense logs  
  - Provide the central detection and analysis platform  

---

# 3. Logging Pipeline

All Windows hosts send telemetry using Splunk Universal Forwarders.

## 3.1 Windows Event Logs  
- Authentication events  
- Privilege changes  
- Process creation events  
Used for: *Credential Access, Lateral Movement, Account misuse*

## 3.2 Sysmon Logs (SwiftOnSecurity Config)  
- Process creation  
- Network connections  
- File creation  
- Registry modifications  
Used for: *Execution, Persistence, Defense Evasion, Discovery, Collection*

## 3.3 PowerShell Logs (4104 Script Block)  
- Script content  
- Encoded/obfuscated commands  
- Module loading  
Used for: *Execution, Discovery, Credential Access, C2 detection*

## 3.4 Network Telemetry (Suricata + pfSense)  
- IDS alerts  
- Traffic metadata  
- DNS queries  
- Firewall logs  
Used for: *Command & Control, Lateral Movement, Exfiltration*

---

# Index Mapping

| Source                 | Splunk Index |
|------------------------|--------------|
| Windows Event Logs     | `index=windows` |
| Sysmon                 | `index=sysmon` |
| PowerShell             | `index=powershell` |
| Suricata IDS           | `index=ids` |
| pfSense Syslogs        | `index=network` |

---

# Log Validation Commands

```
index=windows    earliest=-5m
index=sysmon     earliest=-5m
index=powershell earliest=-5m
index=network    earliest=-5m
index=ids        earliest=-5m
```

---

# 4. Standard Workflow

1. Select MITRE ATT&CK technique  
2. Execute test via Atomic Red Team  
3. Validate logs in Splunk  
4. Build detections  
5. Refine logic and reduce noise  
6. Create alert thresholds  
7. Document findings  

---

# 5. Execution Context

1. All tests initiated from Kali Linux  
2. PowerShell Core (Kali) or PowerShell 7.x (Windows) used depending on technique  
3. Remote execution uses elevated PowerShell via OpenSSH  
4. Windows 10 clients are the default targets  
5. Windows Defender and Firewall may be disabled to maximize telemetry during testing  

---
