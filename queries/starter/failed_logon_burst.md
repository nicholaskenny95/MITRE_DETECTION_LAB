---
tags:
  - ATTACK/CredentialAccess
  - Telemetry/WindowsEvent
  - Surface/Identity
  - Surface/Network
---
Purpose: Identifies repeated authentication failures indicative of password spray activity.
```
index=windows EventCode=4625 earliest=-1h
| stats count by Account_Name IpAddress
| where count > 5
| sort - count
```
