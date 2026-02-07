# Hidden User via Dollar Sign

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1564.002 ](https://attack.mitre.org/techniques/T1564/002/) | Hidden Users |
| Persistence | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account |

#### Hypothesis
Adversaries often seek to create user accounts for persistence, but they attempt to conceal them from casual inspection to evade detection (T1564.002). One common behavioral convention used by attackers is to create a new user account with a trailing dollar sign.
In Windows, user accounts ending with a dollar sign are typically machine accounts or inter-service accounts (MSAs/gMSAs). They are not intended for interactive logon, and many administrative tools or scripts filter these accounts from output by default.
Therefore, we hypothesize that:
Any user account created that ends with a dollar sign ($) and is not created by a known, authorized system process (like Active Directory components or system setup) is a high-confidence indicator of malicious persistence establishment.

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
#repo.cid != 77bb5e6ffad446f491aad89de6fa8d38
| #event_simpleName = UserAccountCreated
| UserName = /\$$/i
| formatTime(format="%Y-%m-%d %H:%M:%S", as="UserCreationTimestamp", timezone="Africa/Cairo")
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","RpcClientProcessId","cid"], as="Tree")
| rename(field="UserName", as="NewUser")
}, include=[UserCreationTimestamp, ComputerName, Tree, NewUser, RpcClientProcessId], name="UserAccountCreatedT")
| #event_simpleName = ProcessRollup2
| match(table="UserAccountCreatedT", field=[ComputerName, TargetProcessId], column=[ComputerName, RpcClientProcessId], nrows=max)
| rename(field="UserName", as="Creator")
| groupBy([UserCreationTimestamp, ComputerName, Creator, Tree, ParentBaseFileName, FileName, CommandLine, NewUser])
```
---
