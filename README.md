# MITRE ATT&CK Detection Lab  

This repository documents a complete, end-to-end detection engineering workflow built on the MITRE ATT&CK framework.  
It includes a fully configured Active Directory lab, Atomic Red Team simulations, Splunk detections, and analysis notes for each tactic.

This project demonstrates:
- Adversary emulation using Atomic Red Team  
- Detection development in Splunk  
- Windows + Sysmon telemetry analysis  
- Network visibility via pfSense and Suricata IDS  
- Documentation aligned with MITRE ATT&CK

---

## Repository Structure

```
/environment/        → Lab environment reference  
/tactics/            → 14 MITRE ATT&CK tactic files  
/playbooks/          → Detection playbook index  
/queries/            → Starter and advanced SPL queries  
/reports/            → Technique-specific lab reports  
README.md            → Repository overview  
```

---

## Included Deliverables

### 1. Lab Environment Documentation
A consistent reference describing:
- Network layout  
- Virtual machine roles  
- Logging pipeline  
- Index mapping  
- Standard workflow  
- Execution context  

### 2. MITRE ATT&CK Tactic Breakdown (14 Files)
Each tactic file includes:
- Sub-techniques  
- Expected surfaces  
- What to look for  
- Starter Splunk queries  
- Enhancements and engineering notes 

### 3. Detection Development Workflow
Used uniformly across all lab reports:
1. Select ATT&CK technique  
2. Execute via Atomic Red Team  
3. Validate telemetry  
4. Build and refine Splunk detections  
5. Document findings and investigative notes  

---

## How to Navigate This Repository

### If you're reviewing my detection capabilities:
Start with `/tactics/` to view threat behavior and detection logic.

### If you want to see hands-on execution:
Open `/reports/` for documented lab simulations per technique.

### If you're interested in lab setup:
Refer to `/environment/Environment.md`.

---

## Technology Stack

- Splunk (SIEM & detections)  
- Sysmon (deep Windows telemetry)  
- Windows Event Logs  
- PowerShell Script Block Logging  
- pfSense (routing + firewall logs)  
- Suricata IDS (network threat detection)  
- Atomic Red Team (execution framework)

---

## About This Project

This portfolio demonstrates real-world security engineering skills:
- Attack emulation  
- Threat detection  
- Log analysis  
- Adversary behavior understanding  
- Structured documentation and reporting  

---

## Contact  
For questions or discussion:  
**Email:** nicholasdkenny95@gmail.com

