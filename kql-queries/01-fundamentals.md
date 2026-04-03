# KQL Fundamentals

Core KQL (Kusto Query Language) concepts and queries for security operations. These queries form the foundation for threat hunting and incident investigation in Microsoft Sentinel and Defender XDR.

## Table of Contents

- [Basic Operators](#basic-operators)
- [Filtering and Searching](#filtering-and-searching)
- [Time Operations](#time-operations)
- [Aggregation and Summarization](#aggregation-and-summarization)
- [Joining Tables](#joining-tables)
- [String Operations](#string-operations)
- [Practical Security Queries](#practical-security-queries)

---

## Basic Operators

### where: Filter rows based on a condition

```kql
SigninLogs
| where ResultType != 0
```

**What it does:** Returns all failed sign-in attempts from Azure AD.
**Why it matters:** Failed sign-ins are one of the first indicators of brute force attacks or credential stuffing.

### project: Select specific columns

```kql
SigninLogs
| where ResultType != 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultDescription
```

**What it does:** Narrows the output to only relevant columns.
**Why it matters:** SOC analysts need to quickly identify who, when, from where, and why a sign-in failed. Removing noise speeds up investigation.

### sort / order by: Sort results

```kql
SigninLogs
| where ResultType != 0
| project TimeGenerated, UserPrincipalName, IPAddress
| sort by TimeGenerated desc
```

**What it does:** Shows the most recent failed sign-ins first.
**Why it matters:** During active incident response, you want to see the latest events first.

### take / limit: Get a sample of rows

```kql
SecurityEvent
| take 10
```

**What it does:** Returns 10 random rows from the SecurityEvent table.
**Why it matters:** Useful for exploring unfamiliar tables and understanding their schema.

---

## Filtering and Searching

### Multiple conditions with and/or

```kql
SigninLogs
| where ResultType != 0
    and TimeGenerated > ago(24h)
    and UserPrincipalName contains "admin"
```

**What it does:** Finds failed admin sign-ins in the last 24 hours.
**Why it matters:** Admin account compromise is high-severity. This query is a quick check during incident triage.

### in operator: Match against a list

```kql
SigninLogs
| where ResultType in ("50053", "50126", "50074")
```

**What it does:** Filters for specific error codes (locked account, invalid password, MFA required).
**Why it matters:** Different error codes tell different stories. Grouping them helps identify attack patterns.

### search: Full-text search across tables

```kql
search "malware.exe"
```

**What it does:** Searches all tables in the workspace for the string "malware.exe".
**Why it matters:** When you have an IOC (Indicator of Compromise) but don't know which table contains it.

---

## Time Operations

### ago(): Relative time

```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| summarize AlertCount = count() by AlertName
| sort by AlertCount desc
```

**What it does:** Shows the most common security alerts from the past 7 days.
**Why it matters:** Identifies the noisiest alerts, helps prioritize tuning and investigation.

### between(): Time range

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-04-01) .. datetime(2026-04-03))
| where ResultType != 0
```

**What it does:** Finds failed sign-ins within a specific date range.
**Why it matters:** Useful when investigating a specific incident with a known timeframe.

### bin(): Group time into buckets

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by bin(TimeGenerated, 1h)
| sort by TimeGenerated asc
```

**What it does:** Groups failed sign-ins by hour.
**Why it matters:** Reveals patterns (e.g., spike of failures at 3 AM could indicate automated attack).

---

## Aggregation and Summarization

### summarize with count()

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName
| sort by FailedAttempts desc
| take 10
```

**What it does:** Top 10 users with the most failed sign-ins.
**Why it matters:** Identifies potential brute force targets or users with misconfigured credentials.

### summarize with dcount() (distinct count)

```kql
SigninLogs
| where ResultType != 0
| summarize UniqueIPs = dcount(IPAddress) by UserPrincipalName
| where UniqueIPs > 5
| sort by UniqueIPs desc
```

**What it does:** Finds users whose failed sign-ins come from more than 5 different IP addresses.
**Why it matters:** Multiple source IPs suggest distributed brute force or credential stuffing (not a single user mistyping their password).

### summarize with make_set()

```kql
SigninLogs
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    SourceIPs = make_set(IPAddress),
    Countries = make_set(LocationDetails.countryOrRegion)
    by UserPrincipalName
| where FailedAttempts > 10
```

**What it does:** For each targeted user, collects all source IPs and countries into arrays.
**Why it matters:** Gives the analyst a complete picture of the attack surface for each user in a single row.

---

## Joining Tables

### join: Correlate data across tables

```kql
SigninLogs
| where ResultType != 0
| summarize FailedCount = count() by UserPrincipalName
| where FailedCount > 20
| join kind=inner (
    SigninLogs
    | where ResultType == 0
    | summarize SuccessCount = count() by UserPrincipalName
) on UserPrincipalName
```

**What it does:** Finds users who had 20+ failed sign-ins AND at least one successful sign-in.
**Why it matters:** Failed attempts followed by success is a strong indicator of successful brute force. This is a high-priority alert pattern.

### union: Combine data from multiple tables

```kql
union SecurityAlert, SecurityIncident
| where TimeGenerated > ago(24h)
| project TimeGenerated, Type = $table, Title = coalesce(AlertName, Title)
| sort by TimeGenerated desc
```

**What it does:** Combines alerts and incidents into a single timeline.
**Why it matters:** Gives a unified view of all security events in the last 24 hours.

---

## String Operations

### extract(): Regex extraction

```kql
SecurityEvent
| where EventID == 4625
| extend Domain = extract(@"(.+)\\(.+)", 1, TargetUserName)
| extend Username = extract(@"(.+)\\(.+)", 2, TargetUserName)
```

**What it does:** Splits DOMAIN\username into separate columns.
**Why it matters:** Allows you to analyze which domains and which specific accounts are being targeted.

### parse: Structured extraction

```kql
Syslog
| where SyslogMessage contains "Failed password"
| parse SyslogMessage with * "Failed password for " Username " from " IPAddress " port " *
```

**What it does:** Extracts username and IP from Linux auth failure messages.
**Why it matters:** Syslog messages are unstructured. parse makes them queryable.

---

## Practical Security Queries

### Impossible Travel Detection

```kql
let timeWindow = 1h;
SigninLogs
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, City = LocationDetails.city, Country = LocationDetails.countryOrRegion
| sort by UserPrincipalName asc, TimeGenerated asc
| extend PreviousCity = prev(City), PreviousTime = prev(TimeGenerated), PreviousUser = prev(UserPrincipalName)
| where UserPrincipalName == PreviousUser
    and City != PreviousCity
    and (TimeGenerated - PreviousTime) < timeWindow
```

**What it does:** Detects users who signed in from two different cities within 1 hour.
**Why it matters:** Classic indicator of compromised credentials. One of the most common SOC alert types.

### New Admin Account Creation

```kql
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources[0].modifiedProperties[0].newValue contains "Admin"
| project TimeGenerated, InitiatedBy = InitiatedBy.user.userPrincipalName, NewAdmin = TargetResources[0].userPrincipalName, Role = TargetResources[0].modifiedProperties[0].newValue
```

**What it does:** Detects when someone is added to an admin role in Azure AD.
**Why it matters:** Privilege escalation is a key phase in most attacks. Unauthorized admin creation is a critical alert.

### Mass File Download (Potential Data Exfiltration)

```kql
CloudAppEvents
| where ActionType == "FileDownloaded"
| summarize DownloadCount = count(), Files = make_set(ObjectName) by AccountDisplayName, bin(TimeGenerated, 1h)
| where DownloadCount > 50
```

**What it does:** Detects users downloading more than 50 files in an hour.
**Why it matters:** Could indicate data exfiltration by a compromised account or malicious insider.

---

## Resources

- [KQL Quick Reference (Microsoft)](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/kql-quick-reference)
- [KQL for Cybersecurity course (Christopher Nett)](https://www.udemy.com/course/kql-for-cybersecurity/)
- [Azure Data Explorer Web UI](https://dataexplorer.azure.com/) (free KQL practice)
- [Kusto Detective Agency](https://detective.kusto.io/) (gamified KQL challenges)
