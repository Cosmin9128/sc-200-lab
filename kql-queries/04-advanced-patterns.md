# Advanced KQL Patterns

Complex query patterns for experienced analysts. Includes dynamic thresholds, anomaly detection, and multi-stage correlation.

---

## Dynamic Baseline with Anomaly Detection

```kql
let lookback = 14d;
let threshold_multiplier = 3;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType != 0
| summarize DailyFails = count() by bin(TimeGenerated, 1d)
| summarize AvgFails = avg(DailyFails), StdDev = stdev(DailyFails)
| extend UpperThreshold = AvgFails + (threshold_multiplier * StdDev)
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType != 0
    | summarize TodayFails = count()
) on $left.UpperThreshold == $left.UpperThreshold
| where TodayFails > UpperThreshold
| project TodayFails, AvgFails, StdDev, UpperThreshold, Anomaly = "Yes"
```

**What it does:** Calculates a 14-day baseline of daily failed sign-ins, then flags today as anomalous if it exceeds 3 standard deviations above average.
**Why it matters:** Static thresholds generate too many false positives. Dynamic baselines adapt to your environment.

---

## Multi-Stage Attack Detection

```kql
let recon = SigninLogs
    | where TimeGenerated > ago(4h)
    | where ResultType != 0
    | summarize ReconAttempts = count() by AttackerIP = IPAddress
    | where ReconAttempts > 15;
let success = SigninLogs
    | where TimeGenerated > ago(4h)
    | where ResultType == 0
    | project SuccessIP = IPAddress, CompromisedUser = UserPrincipalName, SuccessTime = TimeGenerated;
let postCompromise = OfficeActivity
    | where TimeGenerated > ago(4h)
    | where Operation in ("New-InboxRule", "FileDownloaded")
    | project PostActionUser = UserId, PostAction = Operation, PostTime = TimeGenerated;
recon
| join kind=inner success on $left.AttackerIP == $right.SuccessIP
| join kind=inner postCompromise on $left.CompromisedUser == $right.PostActionUser
| where PostTime > SuccessTime
| project AttackerIP, CompromisedUser, ReconAttempts, SuccessTime, PostAction, PostTime
```

**What it does:** Correlates three stages: brute force recon, successful login, post-compromise activity.
**Why it matters:** Detects complete attack chains, not just individual events. This is what separates a SOC analyst from an alert monkey.

---

## Rare Process Execution (Living off the Land)

```kql
let commonProcesses = DeviceProcessEvents
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | summarize ExecutionCount = count() by FileName
    | where ExecutionCount > 100
    | project FileName;
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName !in (commonProcesses)
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "explorer.exe")
| summarize FirstSeen = min(TimeGenerated), DeviceCount = dcount(DeviceName), Devices = make_set(DeviceName, 5) by FileName, ProcessCommandLine
| where DeviceCount < 3
| sort by FirstSeen desc
```

**What it does:** Identifies processes that are rare in your environment (not seen regularly in the past 30 days) and were launched from common parent processes.
**Why it matters:** Attackers use legitimate but uncommon tools (LOLBins) to avoid detection.

---

## Template: Add Your Own

```markdown
## [Pattern Name]

​```kql
// Your query here
​```

**What it does:** [Description]
**Why it matters:** [Security relevance]
**Complexity:** [Basic / Intermediate / Advanced]
**Related MITRE:** [Technique IDs]
```
