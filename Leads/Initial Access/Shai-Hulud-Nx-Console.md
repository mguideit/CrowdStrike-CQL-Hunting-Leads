# Shai-Hulud Nx-Console

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Initial Access | [T1195](https://attack.mitre.org/techniques/T1195/001/)  | Compromise Software Dependencies and Development Tools |
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

#### Hypothesis
An adversary may be leveraging the compromised Visual Studio Code extension nrwl.angular-console-18.95.0 to gain initial access, execute malicious code, or compromise developer environments through trusted VSCode extension installations.


#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* [ox.security](https://www.ox.security/blog/teampcp-strikes-again-how-a-trojan-vs-code-extension-brought-down-github/)

#### Tags
`#Hunting`

---

## CrowdStrike (CQL)

```cql
#event_simpleName = ProcessRollup2
| FileName = Code.exe
| CommandLine = /\.vscode\\extensions\\(?<ExtensionName>[^\\\/\s\"\,]+)/i 
| ExtensionName = /nrwl.angular-console-18.95.0/i // The one caused GitHub Compromise
| groupBy([ExtensionName], function=[count(ComputerName, distinct=true, as="InstalledOn"), collect([ComputerName], limit=20000)], limit=max)
| table(ExtensionName)
```





