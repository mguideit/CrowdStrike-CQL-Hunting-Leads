# Hidden User via SpecialAccounts

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1564.002](https://attack.mitre.org/techniques/T1564/002/) | Hidden Users |

#### Hypothesis
Adversaries seeking stealthy persistence will create a local user account (T1136.001) and immediately attempt to conceal it from the standard Windows Logon screen and Control Panel.

They achieve this by manipulating the Windows Registry, specifically adding a value to the HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist key and setting it to 0.

Since legitimate system administrators rarely need to invisible specific user accounts from the GUI, any registry write or modification to the SpecialAccounts\Userlist key is a high-fidelity indicator of Defense Evasion intended to mask a backdoor account.

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
defineTable(query={
#event_simpleName = RegSystemConfigValueUpdate
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","ContextProcessId","cid"], as="Tree")
| RegObjectName = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist"
| formatTime(format="%Y-%m-%d %H:%M:%S", as="RegTimestamp", timezone="Africa/Cairo")
}, include=[RegTimestamp, ComputerName, Tree, ContextProcessId, RegObjectName, RegValueName, RegOperationType], name="RegSystemConfigValueUpdateT")
| #event_simpleName = ProcessRollup2
| match(table="RegSystemConfigValueUpdateT", field=[ComputerName, TargetProcessId], column=[ComputerName, ContextProcessId])
| groupBy([RegTimestamp, ComputerName, UserName, Tree, ParentBaseFileName, FileName, CommandLine, RegObjectName, RegValueName, RegOperationType])
```
---
