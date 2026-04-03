# Microsoft Sentinel: Analytics Rules

Detection rules configured in Microsoft Sentinel for the SC-200 lab.

---

## Types of Analytics Rules

| Type | Description | SC-200 Relevance |
|------|------------|-------------------|
| Microsoft incident creation | Auto-creates incidents from Defender alerts | Must know |
| Scheduled | Custom KQL queries that run on a schedule | Must know (exam favorite) |
| Fusion | ML-based multi-stage attack detection | Must know concept |
| NRT (Near Real-Time) | Runs every minute, subset of KQL | Must know |
| Anomaly | Built-in ML anomaly detection | Awareness level |

---

## Rule 1: Brute Force Against User Account

**Type:** Scheduled
**Severity:** Medium
**MITRE ATT&CK:** T1110 (Brute Force)

**Rule query:**
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    DistinctIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 5)
    by UserPrincipalName
| where FailedAttempts > 20 and DistinctIPs > 3
```

**Configuration:**
- Run frequency: Every 1 hour
- Lookup data from: Last 1 hour
- Alert threshold: Greater than 0
- Entity mapping: Account = UserPrincipalName, IP = IPs
- Incident grouping: Group alerts into a single incident per UserPrincipalName

**Setup steps:**
1. Sentinel > Analytics > Create > Scheduled query rule
2. Fill in name, description, severity, MITRE tactics
3. Paste the query in the Rule query field
4. Set the schedule and threshold
5. Map entities
6. Configure incident settings
7. Review and Create

---

## Rule 2: Suspicious Inbox Rule Creation

**Type:** Scheduled
**Severity:** High
**MITRE ATT&CK:** T1114.003 (Email Collection: Email Forwarding Rule)

**Rule query:**
```kql
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("ForwardTo", "RedirectTo", "DeleteMessage", "ForwardAsAttachmentTo")
| project TimeGenerated, UserId, Operation, Parameters, ClientIP
```

**Configuration:**
- Run frequency: Every 15 minutes
- Lookup data from: Last 15 minutes
- Alert threshold: Greater than 0
- Entity mapping: Account = UserId, IP = ClientIP

---

## Rule 3: Admin Role Assignment

**Type:** NRT (Near Real-Time)
**Severity:** High
**MITRE ATT&CK:** T1098 (Account Manipulation)

**Rule query:**
```kql
AuditLogs
| where OperationName == "Add member to role"
| extend Role = tostring(TargetResources[0].modifiedProperties[0].newValue)
| where Role has "Admin"
| project TimeGenerated, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName), TargetUser = tostring(TargetResources[0].userPrincipalName), Role
```

**NRT Note:** Near Real-Time rules run every minute but have limitations: no lookback window configuration, limited KQL operators.

---

## Template: Add New Rules

```markdown
## Rule: [Name]

**Type:** [Scheduled / NRT / Fusion]
**Severity:** [Informational / Low / Medium / High]
**MITRE ATT&CK:** [Technique]

**Rule query:**
​```kql
// Detection query here
​```

**Configuration:**
- Run frequency: [interval]
- Lookup data from: [timespan]
- Alert threshold: [value]
- Entity mapping: [entities]

**False positive handling:** [Known benign scenarios]
**Setup steps:** [Step by step with screenshots]
```
