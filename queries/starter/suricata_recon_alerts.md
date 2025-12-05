---
tags:
  - ATTACK/Reconnaissance
  - Telemetry/Suricata
  - Surface/Network
---
Purpose: Flags IDS alerts indicating reconnaissance behavior such as scanning or probing activity.
```
index=ids earliest=-1h
| stats count by src_ip dest_ip dest_port signature
| sort - count
```
