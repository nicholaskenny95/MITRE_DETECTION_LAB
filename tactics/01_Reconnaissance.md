---
tags:
  - ATTACK/Reconnaissance
  - Surface/Network
  - Surface/Process
  - Telemetry/Sysmon
  - Telemetry/pfSense
  - Telemetry/Suricata
---
# Reconnaissance (TA0043)

Reconnaissance involves adversaries gathering information, either actively or passively, that helps them plan future operations. This can include details about the organization, infrastructure, or personnel, which can later be used for tactics like gaining initial access, prioritizing post-compromise actions, or guiding further reconnaissance efforts.

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

- [Internal Connection Bursts](internal_connection_bursts.md)
- [Suricata Recon Alerts](suricata_recon_alerts.md)
- [Local Recon Tool Execution](local_recon_tool_execution.md)
- [Horizontal Target Spread](horizontal_target_spread.md)
## Enhancements

### Telemetry Notes
- Slow scans may evade Suricata; use pfSense or Sysmon EventCode 3 for visibility.  
- Workstation scanning is almost always malicious.

### Detection Engineering Tips
- Correlate Sysmon 1 (process creation) with Sysmon 3 (network connections).  
- Add asset roles to prioritize events.  
- Combine network + process behavior for higher fidelity.
