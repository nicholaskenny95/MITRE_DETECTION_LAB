---
tags:
  - ATTACK/Reconnaissance
  - Telemetry/pfSense
  - Surface/Network
---
Purpose: Identifies hosts establishing an unusually high volume of internal connections, a pattern common in lateral scanning.
```
index=network earliest=-1h
| stats count by src_ip dest_ip dest_port
| where count > 20
| sort - count
```
