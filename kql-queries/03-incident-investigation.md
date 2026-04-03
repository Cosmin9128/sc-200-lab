# KQL for Incident Investigation

Queries used during active incident investigation and triage in Microsoft Sentinel and Defender XDR.

---

## User Activity Timeline

```kql
let targetUser = "user@domain.com";
let investigationWindow = 24h;
union SigninLogs, AuditLogs, OfficeActivity
| where TimeGenerated > ago(investigationWindow)
| where UserPrincipalName == targetUser or UserId == targetUser
| project TimeGenerated, Activity = coalesce(OperationName, Operation, ResultType), Source = $table, IPAddress, Details = coalesce(ResultDescription, Parameters)
| sort by TimeGenerated asc
```

**Use case:** Build a complete timeline of a specific user's activity across all data sources.
**When to use:** First step when investigating a potentially compromised account.

---

## IP Reputation Check

```kql
let suspiciousIP = "203.0.113.50";
union SigninLogs, SecurityEvent, CommonSecurityLog
| where TimeGenerated > ago(30d)
| where IPAddress == suspiciousIP or SourceIP == suspiciousIP
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    EventCount = count(),
    AffectedUsers = make_set(coalesce(UserPrincipalName, Account), 20),
    Tables = make_set($table)
```

**Use case:** Check how long a suspicious IP has been active in your environment and what it accessed.
**When to use:** After identifying a suspicious IP from an alert or threat intel feed.

---

## Device Compromise Assessment

```kql
let targetDevice = "WORKSTATION-01";
DeviceProcessEvents
| where TimeGenerated > ago(48h)
| where DeviceName =~ targetDevice
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| sort by TimeGenerated asc
```

**Use case:** Review all potentially suspicious process executions on a specific device.
**When to use:** When a device triggers a malware or suspicious behavior alert.

---

## Email Investigation (Phishing)

```kql
EmailEvents
| where TimeGenerated > ago(48h)
| where SenderFromAddress == "phishing@suspicious-domain.com"
| summarize
    Recipients = make_set(RecipientEmailAddress),
    RecipientCount = dcount(RecipientEmailAddress),
    Subjects = make_set(Subject)
| extend Severity = iff(RecipientCount > 10, "High (mass phishing)", "Medium (targeted)")
```

**Use case:** Assess the scope of a phishing campaign by checking how many users received the email.
**When to use:** After a user reports a phishing email or an email alert triggers.

---

## Post-Compromise: What Did the Attacker Access?

```kql
let compromisedUser = "user@domain.com";
let compromiseTime = datetime(2026-04-02T14:00:00Z);
OfficeActivity
| where TimeGenerated > compromiseTime
| where UserId == compromisedUser
| where Operation in ("FileAccessed", "FileDownloaded", "FileCopied", "FileModified", "MailItemsAccessed", "Send")
| project TimeGenerated, Operation, OfficeObjectId, ClientIP
| sort by TimeGenerated asc
```

**Use case:** Determine what data the attacker accessed after compromising an account.
**When to use:** After confirming account compromise, to assess data exposure and impact.

---

## Resources

- [Microsoft Sentinel Investigation Guide](https://learn.microsoft.com/en-us/azure/sentinel/investigate-cases)
- [Incident Response Reference Guide (NIST)](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
