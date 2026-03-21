# Bitsadmin.exe BITSJobCreated

#### MITRE ATT&CK Mapping
| Tactic | Technique ID | Title |
| :--- | :--- | :--- |
| Defense Evasion | [T1197](https://attack.mitre.org/techniques/T1197/) | BITS Jobs |

#### Hypothesis

Attackers are creating Background Intelligent Transfer Service (BITS) jobs to stage, download, or exfiltrate files, potentially for persistent access, command and control, or data manipulation. Unusual BITS job creations, particularly by non-system users and for non-browser-related files, warrant investigation as they could indicate malicious activity.


1- #event_simpleName = BITSJobCreated: Focuses on events where a BITS job is created—key to detecting T1197 activity.

2- UserName != "" and not SYSTEM or machine$: Targets actual user-initiated jobs—ignoring system or idle service contexts.

3- TargetFileName != /…/AppData/Local|chrome|edge|mozilla/: Excludes common benign downloads from browser-based or local cache directories.

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
#event_simpleName = BITSJobCreated
| UserName != "" UserName != /SYSTEM|\$/i UserName = *
| TargetFileName != /\\AppData\\Local|chrome|edge|mozilla|ccmsetup|\\HP/i
| rename(field="TargetFileName", as="DownloadedFile")
| formatTime(format="%Y-%m-%d %H:%M:%S", as="BITSJobTimeStamp", timezone="Africa/Cairo")
| format("https://falcon.us-2.crowdstrike.com/graphs/process-explorer/tree?id=pid:%25s:%25s&investigate=true&_cid=%25s", field=["aid","RpcClientProcessId","cid"], as="Tree")
}, include=[BITSJobTimeStamp, ComputerName, RpcClientProcessId, UserName, Tree, DownloadedFile], name="BITSJobCreatedT")
| #event_simpleName = ProcessRollup2
| match(table="BITSJobCreatedT", field=[ComputerName, TargetProcessId], column=[ComputerName, RpcClientProcessId], nrows=max)
| rename(field="FileName", as="DownloaderProcess")
| rename(field="ParentBaseFileName", as="DownloaderProcessParent")
| rename(field="CommandLine", as="DownloaderProcessCommandLine")
| rename(field="SHA256HashData", as="DownloaderProcesSHA256HashData")
// Exclusion
| DownloaderProcess != /OneDrive|acad/i
| groupBy([BITSJobTimeStamp, ComputerName, UserName, Tree, DownloadedFile, DownloaderProcess, DownloaderProcessParent, DownloaderProcessCommandLine, DownloaderProcesSHA256HashData])
```
---
