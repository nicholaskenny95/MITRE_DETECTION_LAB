---
tags:
  - ATTACK/CommandAndControl
  - Sysmon
  - Suricata
  - pfSense
  - Surface/Network
  - Surface/Process
---

# Command and Control (TA0011)

Command and Control (C2) techniques enable adversaries to communicate with and remotely control compromised systems.  
In your lab, C2 commonly appears as **PowerShell-based callbacks**, **HTTP/HTTPS beacons**, **encoded commands**, and **unexpected outbound network connections**.

---

## Common Sub-Techniques

**T1071 – Application Layer Protocol**  
HTTP/HTTPS, DNS, or other application protocols used for C2 channels.

**T1573 – Encrypted Channel**  
TLS/SSL-encrypted communication to mask malicious traffic.

**T1105 – Ingress Tool Transfer**  
Sending tools/payloads over the active C2 channel.

---

## Expected Surfaces

**Network** – primary source of C2 visibility (outbound connections, periodic beacons)  
**Process** – script engines or LOLBins generating callbacks  
**File System** – rarely used, except for dropped payloads prior to callback

---

## What to Look For

### Network Indicators

- Outbound connections to:
  - Non-lab IPs
  - Cloud/VPS providers
  - Domains not seen elsewhere in the environment
- Repeated periodic traffic at consistent intervals (beaconing)
- Suricata alerts for suspicious or anomalous HTTP/HTTPS patterns
- Traffic over uncommon ports (e.g., 8080, 8443, 9001)

### Process Indicators

- PowerShell invoking:
  - `Invoke-WebRequest`
  - `Invoke-RestMethod`
  - Custom HTTP clients
- Processes making outbound connections shortly after execution
- Script interpreters running in the background or repeated loops

### Behavioral Patterns

- Execution → external callback → follow-on commands  
- Periodic network connections even when user is idle  
- Callback traffic paired with encoded or obfuscated command lines

---

## Starter Splunk Queries

### 1. Outbound Connections to Non-Lab IPs (Sysmon Network Events)
```
index=sysmon EventCode=3 earliest=-1h
| search DestinationIp!="10.10.*"
| table _time host Image DestinationIp DestinationPort
```

### 2. PowerShell-Based HTTP/HTTPS Callbacks
```
index=powershell earliest=-1h
| search ScriptBlockText="*Invoke-WebRequest*" OR ScriptBlockText="*Invoke-RestMethod*"
| table _time host User ScriptBlockText
```

### 3. Beaconing Behavior (Periodic Connections)
```
index=sysmon EventCode=3 earliest=-1h
| bin _time span=1m
| stats count by _time, DestinationIp, DestinationPort
| where count > 1
```

### 4. Suricata Suspicious C2 Alerts
```
index=ids earliest=-1h
| search signature="*C2*" OR signature="*callback*" OR signature="*malware*"
| table _time src_ip dest_ip dest_port signature
```

---

## Enhancements

### Telemetry Notes

- Sysmon EventCode 3 is crucial for outgoing connection visibility.  
- Suricata may catch known C2 patterns, but many encrypted channels appear benign.

### Detection Engineering Tips

- Combine **process creation** + **network activity** for highest fidelity.  
- Look for repeated intervals (beaconing) to identify persistent C2.  
- Compare outbound hosts against allowlists of internal and approved external services.

---

