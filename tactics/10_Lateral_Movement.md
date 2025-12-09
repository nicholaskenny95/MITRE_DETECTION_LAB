---
tags:
  - ATTACK/LateralMovement
  - Surface/Network
  - Surface/Process
  - Surface/Identity
  - Telemetry/Sysmon
  - Telemetry/WindowsEvent
  - Telemetry/Suricata
---
# Lateral Movement (TA0008)

Lateral Movement involves techniques that allow adversaries to move through a network and control remote systems. To achieve their objectives, they often explore the network, find their target, and then pivot through other systems or accounts. This can be done using remote access tools they install or by leveraging legitimate credentials and built-in network tools, which can be more discreet.

---

## Common Sub-Techniques

**T1021 – Remote Services**  
SMB, WinRM, RDP, and other remote admin protocols used for movement.

**T1027 – Pass the Hash / Pass the Ticket**  
Authentication using stolen credential material.

**T1135 – Network Share Discovery (Often precursor)**  
Accessing ADMIN$, C$, IPC$ or other internal shares.

---

## Expected Surfaces

**Network** – connections to SMB, WinRM, RDP, remote service ports  
**Identity** – authentication attempts, failed and successful  
**Process** – remote execution tools and host-level execution events

---

## What to Look For

### Network Indicators
- Connections on:
  - **445 (SMB)**
  - **5985/5986 (WinRM)**
  - **3389 (RDP)**
  - **135, 139, 49152+ (WMI/DCOM)**  
- Suricata alerts for SMB/WinRM anomalies  
- Lateral movement originating from non-admin workstations

### Identity Indicators
- **4624 LogonType 3** (network) from unusual hosts  
- **4624 LogonType 10** (RDP) from unexpected sources  
- **4625 failed attempts** followed by a successful logon

### Process Indicators
- Commands like:
  - `psexec.exe`, `wmic.exe`, `winrm.vbs`
  - PowerShell remoting: `Enter-PSSession`, `Invoke-Command`  
- Creation of remote services (paired with privilege escalation)

### Behavioral Patterns
- Credential Access → Lateral Movement → Execution on new host  
- Repeated authentication attempts across several hosts  
- Remote execution followed by suspicious child processes

---

## Starter Splunk Queries

- [RDP, SMB, and WinRM Session Attempts](remote_session_attempts.md)
- [Authentication Events for Remote Logons](remote_authentication_events.md)
- [Remote Execution Tools Launched](remote_execution_tools.md)
- [ADMIN$, C$, and IPC$ Share Access via SMB](admin_share_enumeration.md)

---

## Enhancements

### Telemetry Notes
- Sysmon EventCode 3 visibility across hosts is essential for spotting lateral network activity.  
- RDP logons use EventCode 4624 LogonType 10; SMB/WinRM use LogonType 3.  
- Administrative shares (ADMIN$, C$, IPC$) access is highly suspicious on workstations.

### Detection Engineering Tips
- Correlate remote logon → remote execution tool → process creation on the target host.  
- Build rules for unexpected east-west connections between workstations.  
- Look for movement immediately after credential dumping on the origin host.

---
