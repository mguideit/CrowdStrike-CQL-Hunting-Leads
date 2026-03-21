# WMIC  Malicious Code Execution via /FORMAT XSL

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1220](https://attack.mitre.org/techniques/T1220/) | XSL Script Processing |

#### Hypothesis
Adversaries may exploit WMIC’s /FORMAT switch to achieve stealthy code execution by crafting a malicious Extensible Stylesheet Language (.xsl) file. This technique leverages script content (e.g., JScript, VBScript) embedded in the .xsl file to execute code, potentially spawning processes with wmic.exe as the parent.

#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* 

#### Tags
`#Hunting` `#LOLBins`

---

## CrowdStrike (CQL)

```cql
event_platform=Win #event_simpleName = ProcessRollup2 ((FileName = /wmic\.exe/i CommandLine = /\/format\:.+\.xsl/i) or (ParentBaseFileName = /wmic\.exe/i  FileName != /conhost\.exe|werfault\.exe/i))
| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38 
| CommandLine != /\/format\:list|\/format\:csv/i
| ComputerName != /Valu/i| formatTime(format="%m/%d/%Y %H:%M:%S %a", as="TimeStamp", timezone="Africa/Cairo")
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","TargetProcessId","cid"], as="Tree") 
| groupBy([CommandLine], function=[count(ComputerName, distinct=true, as="UniqComputercount"), collect([TimeStamp, ComputerName, UserName, GrandParentBaseFileName, ParentBaseFileName, FileName])], limit=max)
| UniqComputercount < 5| groupBy([TimeStamp, ComputerName, UserName, Tree, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine])
```
---