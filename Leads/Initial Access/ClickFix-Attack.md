# ClickFix Attack

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Initial Access | [T1189](https://attack.mitre.org/techniques/T1189/)  | Drive-by Compromise |
| Defense Evasion | [T1202](https://attack.mitre.org/techniques/T1202/) | Indirect Command Execution |
| Command and Control | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS |

#### Hypothesis
If adversaries are using the Windows nslookup utility via social engineering lures (ClickFix) to perform custom DNS lookups that return encoded payloads, then monitoring for unusual or scripted nslookup usage, especially against non-corporate or externally hardcoded DNS servers, as part of a staged malware delivery chain will reveal early signs of this attack and allow defenders to detect the staging and execution of malicious artifacts before full compromise.


#### Platform
* **CrowdStrike Falcon**

#### Author
* **Muhammad Hassoub**

#### References
* [thehackernews.com](https://thehackernews.com/2026/02/microsoft-discloses-dns-based-clickfix.html)

#### Tags
`#Hunting`

---

## CrowdStrike (CQL)

```cql
// ClickFix: Forensic Discovery of RunMRU Command Injection
// To find the "smoking gun" in the registry. This identifies the exact command the user was coerced into pasting.
#event_simpleName = RegSystemConfigValueUpdate
| RegObjectName = /\\REGISTRY\\USER\\.+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU/i
| rename(field="RegStringValue", as="RunCommand")
| length("RunCommand", as=RunCommandLength)
| RunCommandLength > 50
// Exclusions
| RunCommand != /EFG-Hermes|\\\\|shell\:\:/i
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","ContextProcessId","cid"], as="Tree")
| groupBy([ComputerName, Tree, RunCommand, RunCommandLength])
```

```cql
// ClickFix: Behavioral Detection of Nslookup-Driven DNS Staging
// To detect the live execution of the variant. It specifically looks for explorer.exe (the Run dialog parent) spawning nslookup.exe. This catches the moment the DNS-based payload is being pulled from the rogue server's "Name" field.
#event_simpleName = ProcessRollup2
| FileName = "nslookup.exe"
| ParentBaseFileName = "explorer.exe"
// Exclusions
| CommandLine != "\\??\\C:\\windows\\system32\\conhost.exe 0xffffffff -ForceV1"
| CommandLine != "\"C:\\windows\\system32\\nslookup.exe\" "
| format("[Tree](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%s:%s&investigate=true&_cid=%s )", field=["aid","TargetProcessId","cid"], as="Tree")
| groupBy([ComputerName, UserName, Tree, FileName, CommandLine])
```




