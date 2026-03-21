# MSBuild Custom Logger DLL Abuse

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1127.001](https://attack.mitre.org/techniques/T1127/001/) | MSBuild |

#### Hypothesis
If msbuild.exe is invoked with a /logger: parameter that loads an arbitrary DLL (i.e., a custom logger DLL), it is likely being abused by an adversary to execute malicious code using a trusted Windows utility. This is highly suspicious when the DLL path is not part of standard build tooling (e.g. not JetBrains Rider) and is commonly indicative of post‑exploitation behaviors where MSBuild is used for fileless or obfuscated code execution.


Abuse Example:

#Executes generated Logger DLL file with TargetLogger export.
msbuild.exe /logger:TargetLogger,C:\Windows\Temp\file.dll;MyParameters,Foo

#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* https://lolbas-project.github.io/lolbas/Binaries/Msbuild/

#### Tags
`#Hunting` `#LOLBins`

---

## CrowdStrike (CQL)

```cql
event_platform=Win #event_simpleName = ProcessRollup2 FileName = /msbuild\.exe/i
| CommandLine = /\/logger|\-logger/i
| DLLPath != /Program Files\\JetBrains\\Rider/i
// Exclusions
| ParentBaseFileName != /Rider\.Backend/i
| formatTime(format="%m/%d/%Y %H:%M:%S %a", as="TimeStamp", timezone="Africa/Cairo")
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="Tree")
| groupBy([TimeStamp, ComputerName, UserName, Tree, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine], function=[count(ComputerName, distinct=true, as="UnqiComputercount")], limit=max)
```
---