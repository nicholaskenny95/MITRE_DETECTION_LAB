---
tags:
  - Index
---
# Unified MITRE ATT&CK Detection Reference

This index page provides a central navigation hub for all detection playbook content in this repository.  
Each MITRE ATT&CK tactic links directly to its corresponding detailed detection file, including:
- Expected telemetry surfaces  
- What to look for  
- Starter Splunk queries  
- Detection engineering enhancements  

Use this page as the primary entry point when exploring or reviewing the detection logic across the lab.

---

# MITRE ATT&CK Tactic Index

| MITRE Tactic                      | Description                                         | Link                                                             |
| --------------------------------- | --------------------------------------------------- | ---------------------------------------------------------------- |
| **Reconnaissance (TA0043)**       | Mapping environment, scanning, probing              | [01_Reconnaissance](../tactics/01_Reconnaissance.md)             |
| **Resource Development (TA0042)** | Preparing infrastructure, staging tools             | [02_Resource_Development](../tactics/02_Resource_Development.md) |
| **Initial Access (TA0001)**       | First entry via phishing, exploits, remote services | [03_Initial_Access](../tactics/03_Initial_Access.md)             |
| **Execution (TA0002)**            | Running attacker-controlled code                    | [04_Execution](../tactics/04_Execution.md)                       |
| **Persistence (TA0003)**          | Maintaining access after reboots/changes            | [05_Persistence](../tactics/05_Persistence.md)                   |
| **Privilege Escalation (TA0004)** | Gaining higher-level permissions                    | [06_Privilege_Escalation](../tactics/06_Privilege_Escalation.md) |
| **Defense Evasion (TA0005)**      | Avoiding detection, disabling logging               | [07_Defense_Evasion](../tactics/07_Defense_Evasion.md)           |
| **Credential Access (TA0006)**    | Stealing passwords, tokens, hashes                  | [08_Credential_Access](../tactics/08_Credential_Access.md)       |
| **Discovery (TA0007)**            | Enumerating systems, users, environment             | [09_Discovery](../tactics/09_Discovery.md)                       |
| **Lateral Movement (TA0008)**     | Moving between internal hosts                       | [10_Lateral_Movement](../tactics/10_Lateral_Movement.md)         |
| **Collection (TA0009)**           | Gathering data for exfiltration                     | [11_Collection](../tactics/11_Collection.md)                     |
| **Command & Control (TA0011)**    | Remote communication with compromised hosts         | [12_Command_and_Control](../tactics/12_Command_and_Control.md)   |
| **Exfiltration (TA0010)**         | Extracting data from the environment                | [13_Exfiltration](../tactics/13_Exfiltration.md)                 |
| **Impact (TA0040)**               | Destroying, encrypting, or manipulating data        | [14_Impact](../tactics/14_Impact.md)                             |

---

# Navigation Aids

## Surface-Based Filtering  
Each tactic file is tagged with the relevant telemetry surfaces:
- `Surface.Process`
- `Surface.File`
- `Surface.Registry`
- `Surface.Network`
- `Surface.Identity`

## Telemetry-Based Filtering  
Filter by logging sources used in detections:
- `Sysmon`
- `WindowsSecurity`
- `PowerShell`
- `Suricata`
- `pfSense`

---

# Usage

Use this index to:
- Navigate all tactic files  
- Understand detection surface coverage  
- Begin investigations from the correct tactic  
- Cross-reference queries and detection logic  
- Plan future detection expansion  

---
