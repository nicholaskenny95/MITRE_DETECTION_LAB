---
tags:
  - ATTACK/CommandAndControl
  - Telemetry/Suricata
  - Surface/Network
---
Purpose: Detects IDS signatures associated with known command-and-control channels or callback behavior.
```
index=ids earliest=-1h
| search signature="*C2*" OR signature="*callback*" OR signature="*malware*"
| table _time src_ip dest_ip dest_port signature
```
