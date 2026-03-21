# Rare MsBuild Execution

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1127.001](https://attack.mitre.org/techniques/T1127/001/) | MSBuild |

#### Hypothesis
Attackers may leverage MSBuild.exe, a trusted developer utility, to execute malicious code in environments where it’s not commonly used—especially when invoked by unusual parents or from uncommon paths, with rare occurrence across hosts and potentially spawning suspicious child processes or network connections.

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
event_platform=Win #event_simpleName=/ProcessRollup/i FileName = /msbuild\.exe/i
| CommandLine != /\\Microsoft Visual Studio|\/Microsoft Visual Studio\/|JetBrains/i
| ParentBaseFileName != /devenv\.exe|node\.exe|MSBuild\.exe|Rider\.Backend\.exe/i
| formatTime(format="%m/%d/%Y %H:%M:%S %a", as="TimeStamp", timezone="Africa/Cairo")
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","TargetProcessId","cid"], as="Tree")
| groupBy([ParentBaseFileName, FileName, CommandLine], function=[count(ComputerName, distinct=true, as=UniqComputerCount), collect([TimeStamp, ComputerName, UserName, Tree])])
| UniqComputerCount < 5
| select([TimeStamp, ComputerName, UserName, UniqComputerCount, Tree, ParentBaseFileName, FileName, CommandLine])| sort([UniqComputerCount, ComputerName])
```
---