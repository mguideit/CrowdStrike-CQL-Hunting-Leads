# [Lead Name]

#### MITRE ATT&CK Technique(s)
| Technique ID | Title |
| --- | --- |
| [TXXXX](URL) | Technique Name |

#### Hypothesis
[Write a clear, 2-3 sentence explanation of the adversary behavior you are looking for and what the expected telemetry looks like.]

#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* [Link to Research/Blog]

#### Tags
`#Hunting` `#TacticName` `#Falcon`

---

## CrowdStrike (CQL)

```cql
// Description: Brief summary of what this specific query does
#event_simpleName = ...
| ...
| groupBy([...])
