# KQL for Threat Hunting

Advanced KQL queries designed for proactive threat hunting in Microsoft Sentinel. Each query targets specific MITRE ATT&CK techniques.

---

## Brute Force Detection (T1110)

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    DistinctIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 10),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by UserPrincipalName
| where FailedAttempts > 25 and DistinctIPs > 3
| extend AttackDuration = LastAttempt - FirstAttempt
| sort by FailedAttempts desc
```

**MITRE ATT&CK:** T1110 (Brute Force)
**What it detects:** Users targeted by 25+ failed sign-ins from 3+ different IPs in 24 hours.
**SOC Action:** Check if any successful login followed the failures. If yes, escalate as potential account compromise.

---

## Password Spray Detection (T1110.003)

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "50126" // Invalid username or password
| summarize
    TargetedUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 20),
    AttemptCount = count()
    by IPAddress
| where TargetedUsers > 10
| sort by TargetedUsers desc
```

**MITRE ATT&CK:** T1110.003 (Password Spraying)
**What it detects:** Single IP trying the same password against many different accounts.
**SOC Action:** Block the source IP. Check if any targeted accounts had a successful login afterward.

---

## Suspicious PowerShell Execution (T1059.001)

```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "Invoke-Expression",
    "IEX",
    "DownloadString",
    "EncodedCommand",
    "-enc",
    "Invoke-WebRequest",
    "Net.WebClient",
    "Start-BitsTransfer",
    "bypass"
)
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated desc
```

**MITRE ATT&CK:** T1059.001 (PowerShell)
**What it detects:** PowerShell commands using common malicious patterns (download cradles, encoded commands, execution policy bypass).
**SOC Action:** Analyze the full command line. Check what was downloaded or executed. Isolate the device if confirmed malicious.

---

## Anomalous Login Locations (T1078)

```kql
let baseline = SigninLogs
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | where ResultType == 0
    | summarize KnownCountries = make_set(LocationDetails.countryOrRegion) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| join kind=inner baseline on UserPrincipalName
| where KnownCountries !contains Country
| project TimeGenerated, UserPrincipalName, Country, IPAddress, KnownCountries, AppDisplayName
```

**MITRE ATT&CK:** T1078 (Valid Accounts)
**What it detects:** Successful logins from countries the user has never signed in from before (30-day baseline).
**SOC Action:** Contact the user to verify. If unrecognized, revoke sessions and force password reset.

---

## Mailbox Rule Manipulation (T1114.003)

```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
| where Parameters has_any ("DeleteMessage", "ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "MoveToFolder")
| project TimeGenerated, UserId, Operation, Parameters
| sort by TimeGenerated desc
```

**MITRE ATT&CK:** T1114.003 (Email Collection: Email Forwarding Rule)
**What it detects:** Creation of inbox rules that delete, forward, or redirect emails.
**SOC Action:** Attackers create these rules to hide evidence or exfiltrate data. Remove the rule, check for BEC (Business Email Compromise).

---

## Template for New Hunting Queries

```markdown
## [Query Name] ([MITRE Technique ID])

​```kql
// Your query here
​```

**MITRE ATT&CK:** [Technique ID and Name]
**What it detects:** [Description]
**SOC Action:** [Recommended response steps]
**False Positive Considerations:** [Known benign scenarios that could trigger this]
**Data Source:** [Required table/connector]
```

---

## Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Microsoft Sentinel Hunting Queries (GitHub)](https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries)
- [KQL for Cybersecurity course](https://www.udemy.com/course/kql-for-cybersecurity/)
