# Suspicious Notepad++ Updater DNS Request

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Command and Control | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols |

#### Hypothesis
Adversary may hijack the communication flow of GUP.exe to redirect it toward malicious infrastructure. By modifying the updater's configuration or exploiting the distribution chain, an adversary may force the process to make DNS requests to non-whitelisted domains, enabling the download of secondary payloads from unauthorized C2 servers.

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
// Be wary if GUP.exe makes DNS requests to domains other than the whitelisted below
#event_simpleName = DnsRequest
| ContextBaseFileName = GUP.exe
| !in(field="DomainName", values=["http://notepad-plus-plus.org/", "http://github.com/", "http://release-assets.githubusercontent.com/", "http://ocsp.globalsign.com/", "http://ocsp2.globalsign.com/"])
| groupBy([ComputerName, ContextBaseFileName, DomainName, RemoteIP])
```
---