# Certutil BASE64 Encoding/ Decoding

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1140](https://attack.mitre.org/techniques/T1140/) | Deobfuscate/Decode Files or Information |

#### Hypothesis
Adversaries may abusecertutil.exe, a trusted Windows utility, to encode or decode data, leveraging its legitimate functionality to facilitate data obfuscation, evade detection, and bypass security controls.

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
event_platform=Win #event_simpleName=/ProcessRollup2|SyntheticProcessRollup2/i FileName = certutil.exe| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38| CommandLine = /encode|decode/i| formatTime(format="%m/%d/%Y %H:%M:%S %a", as="TimeStamp", timezone="Africa/Cairo") | format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","TargetProcessId","cid"], as="Tree")| groupBy([TimeStamp, ComputerName, UserName, Tree, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine])
```
---