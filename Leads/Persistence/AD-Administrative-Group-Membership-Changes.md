# AD Administrative Group Membership Changes

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Persistence | [T1098.007](https://attack.mitre.org/techniques/T1098/007/) | Additional Local or Domain Groups |

#### Hypothesis
If a domain account is added to an Active Directory administrative group, especially by unusual actors or from atypical workstations, it may indicate unauthorized privilege escalation or persistence by adversaries targeting domain-wide privilege

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
#event_simpleName = ActiveDirectoryAuditGroupMemberModified
| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38
| rename(field="PerformedOnAccountName", as="PerformedOnGroup")
| rename(field="PerformedOnAccountDomain", as="Domain")
| rename(field="PerformedByAccountObjectName", as="PerformedBy")
| rename(field="GroupMemberAccountName", as="TheImpactedGroupMember")
| rename(field="SourceEndpointAddressIP4", as="RemoteIP")
| PerformedOnGroup = /Admin/i
| PerformedOnGroup != /Administration_OutsourceEmployees|App_Proxy_HC_Admin/i
| ActiveDirectoryAuditActionType = "4" //Filter for member addition events only
| case {ActiveDirectoryAuditActionType = "0" | Performed_Action :="CREATED";
ActiveDirectoryAuditActionType = "1" | Performed_Action :="DELETED";
ActiveDirectoryAuditActionType = "2" | Performed_Action :="MODIFIED";
ActiveDirectoryAuditActionType = "4" | Performed_Action :="GROUP_MEMBER_ADDED";
ActiveDirectoryAuditActionType = "8" | Performed_Action :="GROUP_MEMBER_REMOVED ";
ActiveDirectoryAuditActionType = "10" | Performed_Action :="PASSWORD_CHANGE";
ActiveDirectoryAuditActionType = "20" | Performed_Action :="PASSWORD_RESET";
ActiveDirectoryAuditActionType = "40" | Performed_Action :="ENABLED";
ActiveDirectoryAuditActionType = "80" | Performed_Action :="DISABLED";
ActiveDirectoryAuditActionType = "100" | Performed_Action :="LOCKED";
ActiveDirectoryAuditActionType = "200" | Performed_Action :="UNLOCKED";
ActiveDirectoryAuditActionType = "400" | Performed_Action :="UNDELETED ";
ActiveDirectoryAuditActionType = "800" | Performed_Action :="MOVED";
ActiveDirectoryAuditActionType = "1000" | Performed_Action :="GPO_SETTINGS_VERSION_CHANGED";
}
| groupBy([@timestamp, ComputerName, Performed_Action, PerformedBy, Domain, PerformedOnGroup, TheImpactedGroupMember, TargetDomainControllerHostName, LocalIP, RemoteIP])
```
---