# [Lead Name]

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| [e.g. Execution] | [TXXXX](URL) | Technique Name |
| [e.g. Defense Evasion] | [TXXXX.00X](URL) | Sub-technique Name |

#### Hypothesis
If adversaries are using the Windows nslookup utility via social engineering lures (ClickFix) to perform custom DNS lookups that return encoded payloads, then monitoring for unusual or scripted nslookup usage, especially against non-corporate or externally hardcoded DNS servers, as part of a staged malware delivery chain will reveal early signs of this attack and allow defenders to detect the staging and execution of malicious artifacts before full compromise.

#### Technical Risk
[Briefly explain the impact if this activity is malicious, e.g., "Allows an attacker to bypass EDR detection by hijacking a trusted process."]

#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* [Link to Research/Blog]

#### Tags
`#Hunting` `#TacticName` `#Falcon` `#CQL`

---

## CrowdStrike (CQL)

```cql
// Description: Brief summary of what this specific query does
#event_simpleName = ...
| ...
| groupBy([...])
