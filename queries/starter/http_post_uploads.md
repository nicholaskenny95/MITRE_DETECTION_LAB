---
tags:
  - ATTACK/Exfiltration
  - Telemetry/Suricata
  - Surface/Network
---
**Purpose:** Identifies HTTP POST requests and upload-related IDS signatures that may indicate data exfiltration or unauthorized transfer of files over the network.
```
index=ids earliest=-1h
| search signature="*POST*" OR signature="*UPLOAD*" OR signature="*data exfil*"
| table _time src_ip dest_ip dest_port signature
```
