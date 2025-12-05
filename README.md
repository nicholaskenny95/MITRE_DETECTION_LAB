# MITRE ATT&CK Detection Lab  

This repository serves as a collection of MITRE ATT&CK–based lab reports created from a custom detection engineering environment. Each report walks through a single technique, from execution to reviewing logs, identifying detection opportunities, and documenting the results.

The environment supporting these reports includes an Active Directory domain, Splunk with Sysmon logging, pfSense, and Suricata, providing both host-level and network-level visibility.

What this project highlights:

- Running controlled attack simulations with Atomic Red Team
- Investigating the resulting telemetry in Splunk
- Understanding Windows and Sysmon event patterns
- Observing network activity through Suricata and pfSense
- Producing clear, MITRE-aligned documentation for each technique

---

## Repository Structure

```
/environment/        → Lab environment reference  
/playbooks/          → Detection playbook index  
/queries/            → Starter SPL queries  
/reports/            → Technique-specific lab reports  
/tactics/            → MITRE ATT&CK tactic files 
/tags/               → Tagging reference
/templates/          → Re-usable documents
README.md            → Repository overview  
```

---

## Included Deliverables

### 1. Lab Environment Documentation
A consistent reference describing:
- Network layout  
- Virtual machine roles  
- Logging pipeline  
- Host system specs
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

## About This Project

This project is designed to provide hands-on experience in a simulated business environment. By using Atomic Red Team to generate real-world security scenarios, the lab allows me to practice detecting and analyzing potential threats with Splunk SIEM.

My goals include:
- Building detection skills with real-world data
- Improving log analysis and problem-solving abilities
- Gaining experience with enterprise-level security tools and processes
- Creating an open resource for others interested in cybersecurity

This project is part of my journey into the cybersecurity field, where I’m committed to developing my skills and demonstrating my dedication to learning and growth in a competitive industry.
 
---

## Contact  
For questions or discussion:  
**Email:** nicholasdkenny95@gmail.com

