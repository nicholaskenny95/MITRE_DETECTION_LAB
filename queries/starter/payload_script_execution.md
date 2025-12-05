---
tags:
  - ATTACK/InitialAccess
  - Telemetry/Sysmon
  - Surface/Process
---
Purpose: Detects phishing payload execution via parent/child anomalies.
```
index=sysmon EventCode=1 earliest=-1h
| search ParentImage="*winword.exe*" OR ParentImage="*excel.exe*" 
        OR ParentImage="*outlook.exe*" OR ParentImage="*chrome.exe*" 
        OR ParentImage="*firefox.exe*"
| table _time host ParentImage Image CommandLine User
```

