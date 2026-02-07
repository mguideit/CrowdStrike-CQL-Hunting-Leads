# Obfuscated PowerShell Activity with High Entropy

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1027](https://attack.mitre.org/techniques/T1027/) | PowerShell |
| Execution | [T1027](https://attack.mitre.org/techniques/T1027/) | PowerShell |

#### Hypothesis
Adversaries obufusctae the powershell commands in order to escape the detection. This query will detect encoded powershell based on the parameters passed during process creation. This query will also work if the PowerShell executable is renamed or tampered with since detection is based solely on a regex of the launch string.

#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* 

#### Tags
`#Hunting`

---

## CrowdStrike (CQL)

```cql
#event_simpleName=ProcessRollup2 event_platform=Win FileName = powershell.exe
| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38
| UserName != /itsvc_ansible|bmbahy/i
| CommandLine=/\s+\-(e\s|eC|enc|encodedcommand|encode)\s+/i
| ParentBaseFileName != /gc_worker|gfx_win|Code/i
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","TargetProcessId","cid"], as="Investigate")
| groupby([ComputerName, UserName, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine], function=[stats([count(aid, distinct=true, as="UniqueEndpointCount"), count(aid, as="ExecutionCount")]), collect([Investigate], limit=200000)], limit=max)
| UniqueEndpointCount < 3
| CmdLength := length("CommandLine")
| CommandLine=/\s+\-(e\s|eC|enc|encodedcommand|encode)\s+(?<Base64String>\S+)/i
| B64Entroy := shannonEntropy("Base64String")
| B64Entroy > 3.5
| ParentBaseFileName != /node\.exe|msiexec\.exe|javaw/
| DecodedCommand := base64Decode(Base64String, charset="UTF-16LE")
| DecodedCommand != /Set\-Location|nessus|Wazuh|dbeaver/i
| GrandParentBaseFileName != /SqlCopilotServer\.exe/i
| table([ComputerName, Investigate, UserName, GrandParentBaseFileName, ParentBaseFileName, FileName, UniqueEndpointCount, ExecutionCount, CmdLength,  B64Entroy, DecodedCommand , Base64String])
```
---