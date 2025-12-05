---
tags:
---
# {{Technique_ID}} — {{Technique_Name}}

---

# 1. Technique Overview

**MITRE ATT&CK ID:** {{Technique_ID}}  
**Tactic:** {{Parent_Tactic}}  
**Technique:** {{Technique_Name}}  
**Atomic Test:** `{{Atomic_Test_Command}}`

**Purpose / Threat Summary:**  
{{Purpose_Summary}}

---

# 2. Execution Summary

**Execution Method:** {{Execution_Method}}  
**Target Host:** {{Target_Host}}  
**Privilege Level:** {{Privilege_Level}}  

**Actions Executed:**  
- {{Action_1}}  
- {{Action_2}}  
- {{Action_3}}  

**Expected Artifacts:**  
- {{Expected_Artifact_1}}  
- {{Expected_Artifact_2}}  
- {{Expected_Artifact_3}}  

---

# 3. Telemetry Observed

## Sysmon (index=sysmon)
{{Sysmon_Notes}}  
Example:
```
{{Sysmon_Example}}
```

## PowerShell Logs (index=powershell) *(if applicable)*
{{PowerShell_Notes}}

## Windows Event Logs (index=windows)
{{Windows_Notes}}

## Network / Suricata (index=network / index=ids)
{{Network_Notes}}

---

# 4. Detection Logic

### Queries Used During Analysis
```
{{Query_1}}
```

```
{{Query_2}}
```

**Full query library for this technique:**  
[Open Query File](../queries/{{Technique_ID}}.md)

---

# 5. Tuning & Refinement

**False Positives Encountered:**  
- {{False_Positive_1}}  
- {{False_Positive_2}}

**Noise Reduction Filters Added:**  
```
{{Filter_Block}}
```

**Final Detection Query:**  
```
{{Final_Query}}
```

---

# 6. Findings

**Key Observations:**  
- {{Observation_1}}  
- {{Observation_2}}  
- {{Observation_3}}

**Detection Confidence:** {{Detection_Confidence}}

**Additional Notes:**  
{{Additional_Notes}}

---

# 7. Screenshots (Optional)

```
![Description](../assets/images/{{Technique_ID}}_screenshot.png)
```

---

# End of Report
