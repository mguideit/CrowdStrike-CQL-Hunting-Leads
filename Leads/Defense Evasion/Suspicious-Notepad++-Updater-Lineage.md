# Suspicious Notepad++ Updater Lineage

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution |

#### Hypothesis
Threat actors are leveraging the Notepad++ update mechanism (GUP.exe) to bypass security controls by spawning malicious installers or secondary stages (like update.exe) that deviate from the standard behavior of launching only the legitimate Notepad++ installer or explorer.exe. By monitoring for non-standard child processes of this trusted signed binary, we can identify instances where the update infrastructure has been hijacked to execute unauthorized code.

#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/

#### Tags
`#Hunting`

---

## CrowdStrike (CQL)

```cql
#event_simpleName = "ProcessRollup2"
| ParentBaseFileName = GUP.exe
| FileName != /^npp.+Installer.+exe$|explorer\.exe/i
| groupBy([ParentBaseFileName, FileName, CommandLine, SHA256HashData])
```
---