---
tags:
  - ATTACK/Reconnaissance
  - Sysmon
  - Suricata
  - pfSense
  - Surface/Network
  - Surface/Process
---

# Reconnaissance (TA0043)

Adversary activity focused on gathering information about the target environment before deeper intrusion. Often noisy on the network but quiet on hosts unless internal tools are executed.

## Common Sub-Techniques

**T1046 – Network Service Scanning**  
Identifying exposed ports/services across hosts.

**T1595 – Active Scanning**  
Port, web, or vulnerability scanning from outside or inside the network.

**T1590 – Gather Victim Network Information**  
Enumeration of addressing, topology, or host details.

## Expected Surfaces

**Network** – IDS alerts, port sweeps, connection bursts  
**Process** – internal scanning tool execution

## What to Look For

### Network Indicators
- One host contacting many IPs or ports  
- Suricata alerts for scans/probes  
- Repeated failed connection attempts  
- Non-admin workstations generating scan-like traffic  
- Activity on unusual or sequential ports  

### Host Indicators
- Execution of nmap, masscan, netcat  
- PowerShell scanning: Test-NetConnection, Resolve-DnsName  
- Admin enumeration tools: wmic, nltest, net.exe

### Behavioral Patterns
- Fan-out: one host scanning many  
- Slow scans (evenly spaced connections)  
- Burst scans (many ports quickly)  
- Recon followed by enumeration commands

## Starter Splunk Queries

### 1. Suricata Recon Alerts
```
index=ids earliest=-1h
| stats count by src_ip dest_ip dest_port signature
| sort - count
```

### 2. Internal Connection Bursts
```
index=network earliest=-1h
| stats count by src_ip dest_ip dest_port
| where count > 20
| sort - count
```

### 3. Local Recon Tool Execution (Sysmon)
```
index=sysmon EventCode=1 earliest=-1h
| search Image="*nmap*" OR Image="*masscan*" OR Image="*netcat*"
        OR CommandLine="*scan*" OR CommandLine="*Test-NetConnection*"
| table _time host Image ParentImage CommandLine User
```

### 4. Horizontal Target Spread (Sysmon Network Events)
```
index=sysmon EventCode=3 earliest=-1h
| stats dc(DestinationIp) as unique_targets by host, Image
| where unique_targets > 10
```

## Enhancements

### Telemetry Notes
- Slow scans may evade Suricata; use pfSense or Sysmon EventCode 3 for visibility.  
- Workstation scanning is almost always malicious.

### Detection Engineering Tips
- Correlate Sysmon 1 (process creation) with Sysmon 3 (network connections).  
- Add asset roles to prioritize events.  
- Combine network + process behavior for higher fidelity.
