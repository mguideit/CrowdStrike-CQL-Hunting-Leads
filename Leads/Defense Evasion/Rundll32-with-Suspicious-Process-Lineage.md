# Rundll32 with Suspicious Process Lineage

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Rundll32 |

#### Hypothesis
Rundll32.exe may be involved in suspicious behavior when spawned by unexpected parent processes like winword.exe, excel.exe, or lsass.exe. These processes are typically targeted in attacks involving malicious macros, lateral movement, or system persistence. The query filters for instances where rundll32.exe is launched by these parent processes, excluding known legitimate command lines (e.g., for print job monitoring). The goal is to identify unusual or malicious activity on the system by analyzing process execution patterns.

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
#event_simpleName = ProcessRollup2 FileName = rundll32.exe
| ParentBaseFileName = /(winword|excel|powerpnt|outlook|mshta|cscript|wscript|msaccess|lsass|taskeng|winlogon|schtask|regsvr32|wmiprvse|wsmprovhost)\.exe/i
| CommandLine != /MonitorPrintJobStatus|NetworkDiagnosticsSharing|egy-printsrv|Lenovo|FactSet|Fct|Partners\.dll\, RetrieveFlatFiles|HP\s|cryptext\.dll,CryptExtAddPFX|p7s|shell32.dll,Control_RunDLL/i
| time := formatTime("%Y/%m/%d %H:%M:%S", field=@timestamp, timezone="Egypt")
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="Tree")
| groupBy([FileName, CommandLine], function=[count(ComputerName, distinct=true, as="UniqComputerNameCount"), collect([Tree, time, ComputerName, UserName, GrandParentBaseFileName, ParentBaseFileName])], limit=max)
| UniqComputerNameCount < 6
| table([time, ComputerName, UserName, Tree, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine, UniqComputerNameCount])
| sort(ComputerName, order=desc, limit=20000)
```
---