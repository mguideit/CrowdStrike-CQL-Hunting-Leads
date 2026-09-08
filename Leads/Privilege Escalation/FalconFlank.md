# FalconFlank

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Privilege Escalation | [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation |
| Privilege Escalation | [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism |

#### Hypothesis
An adversary with local access may drop maliciously crafted OLECFB Office files into temporary directories to intentionally trigger CrowdStrike Falcon's Office malicious macro remediation process. By coercing the highly privileged sensor into unsafely handling attacker-controlled, unsigned payloads, the attacker aims to execute arbitrary code and elevate privileges to SYSTEM.

#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* [FalconFlank: CrowdStrike Falcon 0-Day PoC - SOCRadar](https://socradar.io/blog/falconflank-crowdstrike-falcon-0day-poc/)
* [FalconFlank CrowdStrike Privilege Escalation Advisory - Foresiet](https://foresiet.com/blog/falconflank-crowdstrike-privilege-escalation-advisory/)
* [Researcher Publishes CrowdStrike Privilege Escalation Zero Day - Infosecurity Magazine](https://www.infosecurity-magazine.com/news/crowdstrike-privilege-escalation/)

#### Tags
`#Hunting` `#PrivilegeEscalation` `#FalconFlank` `#ZeroDay` `#CrowdStrike` `#CQL`

---

## CrowdStrike (CQL)

```cql
// Description: Hunts for the FalconFlank LPE vulnerability behavior by identifying OLECFB files written to the \Temp\ directory. It joins execution context and specifically flags files lacking embedded signatures (SIGNATURE_FLAG_NO_EMBEDDED_CERT) to highlight suspicious payloads, while generating a direct Process Tree link for rapid triage.
defineTable(query={
  | #event_simpleName = MSDocxFileWritten
  | case {MSOfficeSubType = 1 | MSOfficeSubType := "OLECFB"; *}
  | MSOfficeSubType = "OLECFB"
  | TargetFileName = /Temp/i
}, include=[aid, ComputerName, ContextBaseFileName, ContextProcessId, MSOfficeSubType, TargetFileName], name="MSDocxFileWrittenT")
| #event_simpleName = ProcessRollup2
| match(table="MSDocxFileWrittenT", field=[aid, TargetProcessId], column=[aid, ContextProcessId])
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","TargetProcessId","cid"], as="Tree") 
| format("%X", field=SignInfoFlags, as=SignInfoFlags_Hex)
| SignInfoFlags_Hex = 8000
| case {SignInfoFlags_Hex = 8000 | SignInfoFlags := "SIGNATURE_FLAG_NO_EMBEDDED_CERT"}
| groupBy([ComputerName, UserName, Tree, ParentBaseFileName, MSOfficeSubType, ContextBaseFileName, SignInfoFlags, TargetFileName])
