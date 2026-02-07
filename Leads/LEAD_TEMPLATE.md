# [Lead Name]

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| [e.g. Execution] | [TXXXX](URL) | Technique Name |
| [e.g. Defense Evasion] | [TXXXX.00X](URL) | Sub-technique Name |

#### Hypothesis
[Write a clear, 2-3 sentence explanation of the adversary behavior you are looking for and what the expected telemetry looks like.]

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
