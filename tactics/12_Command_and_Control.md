---
tags:
  - ATTACK/CommandAndControl
  - Surface/Network
  - Surface/Process
  - Telemetry/Sysmon
  - Telemetry/Suricata
  - Telemetry/pfSense
---

# Command and Control (TA0011)

Command and Control involves techniques adversaries use to communicate with and control compromised systems inside a network. They often try to blend in with normal traffic to avoid detection, using different methods depending on the network’s structure and defenses.

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

- [Outbound Connections to External IPs](unknown_outbound_connections.md)
- [PowerShell-Based HTTP/HTTPS Callbacks](powershell_web_callbacks.md)
- [Beaconing Behavior](periodic_beaconing_connections.md)
- [Suspicious C2 Alerts](suspicious_c2_alerts.md)

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

