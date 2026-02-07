# User Account Created and Added to a Group

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Persistence | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account |

#### Hypothesis
Adversaries may establish persistence and elevate privileges by creating a new user account and immediately adding it to a privileged group (e.g., Local Administrators). This behavior may indicate the creation of a backdoor account intended for sustained unauthorized access.

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
defineTable(
  query = {
    #event_simpleName = UserAccountCreated
    | rename(field="UserName", as="CreatedUserName")
    | rename(field="UserRid", as="CUserRid")
    | CreatedUserName != /lenovo_tmp/i
    | formatTime(format="%Y-%m-%d %H:%M", as="TimeStamp", timezone="Africa/Cairo")
  },
  include = [ComputerName, CreatedUserName, RpcClientProcessId, TimeStamp, CUserRid],
  name = "UserAccountCreated"
)
// If same account was added to group
| defineTable(
    query = { 
        #event_simpleName = "UserAccountAddedToGroup"
        | rename(field="UserRid", as="GUserRid")
    },
    include = [ComputerName, RpcClientProcessId, GroupRid, GUserRid],
    name = "UserAccountAddedToGroup"
  )

// Process context events
| #event_simpleName = ProcessRollup2
| rename(field="UserName", as="CreatorUserName")

// Correlate with previously defined tables based on ComputerName and process context
| match(
    table  = "UserAccountCreated",
    field  = [ComputerName, TargetProcessId],
    column = [ComputerName, RpcClientProcessId],
    nrows=max
  )
| match(
    table  = "UserAccountAddedToGroup",
    field  = [ComputerName, TargetProcessId],
    column = [ComputerName, RpcClientProcessId],
    nrows=max
  )

// Map RID values to human-readable group names
| case {
    GroupRid=0000022B | AddedToGroup := "Remote Desktop Users";
    GroupRid=00000221 | AddedToGroup := "Users";
    GroupRid=00000220 | AddedToGroup := "Administrators";
    GroupRid=00000244 | AddedToGroup := "Remote Management Users";
    * | AddedToGroup := "Other";
  }

// Exclude system or service accounts
| CreatorUserName != /\$/i
// Make sure the same user was created and was added to group by same CreatorUserName
| test(GUserRid == CUserRid)
// Add a clickable process tree visualization link
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s)", field = [aid, TargetProcessId, cid], as = "Tree")
// Final grouping and aggregation output
| groupBy([TimeStamp, ComputerName, CreatorUserName, CreatedUserName, AddedToGroup, Tree, ParentBaseFileName, FileName, CommandLine])
```
---
