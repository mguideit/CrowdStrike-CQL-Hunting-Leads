# LOLBins DNS

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Command and Control | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS |

#### Hypothesis
Adversaries may use commonly available command-line utilities or Living off the Land Binaries (LOLBins) to establish C2 (Command and Control) communications with external or suspicious domains. By identifying these behaviors with rare domain destinations, we can surface potential command and control, staging, or initial access activity.

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
defineTable(query={
#event_simpleName = DnsRequest
| #repo.cid != 77bb5e6ffad446f491aad89de6fa8d38
| ContextBaseFileName = /powershell|^(certutil|bitsadmin|mshta|wmic|regsvr32|msiexec|cmd|cscript|wscript|sc|net|ftp|tftp|curl|wget|sftp)\.exe/i
| DomainName = /\./i
| DomainName != /EFG|hermes|EGY-|microsoft\.com|arpa|ADFS|10\.|172\.|digicert|azureedge\.net|192\.|chocolatey\.org|ocsp|thawte\.com|\.local|aka\.ms|outlook\.com|fastly\.net|office365\.com|vmware\.com|microsoftonline\.com|verisign\.com|msecnd\.net|etisalat\.com|symcd\.com|waconazure\.com|bing\.com|sectigo\.com|symcb\.com|slackb|github|(azure\.com|wazuh\.com)$|powershellgallery\.com|elastic\.co|powerbi\.com|msauth\.net|msftauth\.net|akamai\.net|live\.com|apache\.org|arubanetworks\.com|mongodb\.com|microsoftazuread-sso\.com|fp2e7a\.wpc\.phicdn\.net|_ldap|tanmeyah|mozilla\.(com|org)|office\.com|openshift\.com|googleapis\.com|msedge\.net|logitech\.com|windows\.net|skype\.com|java\.com|dot\.net|symantec\.com|hp\.com|gmail\.com|adobe\.com|cribl\.io|msauthimages\.net|bloomberg\.com|captive\.network|valu\.com|googleusercontent\.com|windows\.com|bedayamortgage\.com|googletagmanager\.com|infoblox\.com|nuget.org|telerik\.com|rustup\.rs|azurefd\.net|k8s\.io|fixsim\.com|nitropdf\.com|hsoftware\.com|mason-registry\.dev|yealink\.com|astral\.sh|visualstudio\.com|oneget\.org|vagrantcloud\.com|apps\.cbe|cibeg\.com|entrust\.net|centos\.org|factset\.com|ubuntu\.com|lseg\.com|dtcc.com|pki.goog|startssl|antlr|google\.com|beyondtrust|intel\.com|usertrust\.com|python\.org|comodoca\.com|gitforwindows\.org|antlabs\.com|docker\.io|example\.com|paytabs\.com|tedata\.net|cybral\.com|godaddy\.com|trust-provider\.com|globalsign\.com|pypa\.io|kaspersky\.com|company\.com|jsdelivr\.net|unpkg\.com/i
| case {DomainName = /(?<SLD>(([a-z0-9-]+\.\w+)$))/i; * }
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","ContextProcessId","cid"], as="Tree")
}, include=[ComputerName, DomainName, SLD, Tree, ContextBaseFileName, ContextProcessId], name="DnsRequestT")

| #event_simpleName = ProcessRollup2
| match(table="DnsRequestT", field=[ComputerName, TargetProcessId], column=[ComputerName, ContextProcessId])
// Exclusions
| ParentBaseFileName != /SenseIR\.exe|Cursor\.exe|code/i
| GrandParentBaseFileName != Agent.Worker.exe
| groupBy([SLD], function=[count(ComputerName, distinct=true, as=UniqCount), collect([ComputerName, UserName, ParentBaseFileName, DomainName, SLD, Tree, ContextBaseFileName, GrandParentBaseFileName], limit=200000)], limit=max)
| UniqCount < 6
| table([ComputerName, UserName, GrandParentBaseFileName, ParentBaseFileName, ContextBaseFileName, SLD, DomainName, UniqCount, Tree])
```
---