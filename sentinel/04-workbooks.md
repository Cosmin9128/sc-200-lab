# Microsoft Sentinel: Workbooks

Workbook configurations for security monitoring dashboards.

---

## What Are Workbooks?

Workbooks are interactive dashboards in Sentinel that visualize data from your workspace. They combine KQL queries with charts, tables, and parameters to create monitoring views.

**SC-200 exam focus:** Know how to create, customize, and use workbooks. Know the difference between workbooks and hunting bookmarks.

---

## Workbook 1: Sign-in Overview Dashboard

**Purpose:** Monitor authentication activity across the organization.

**Queries used:**

Failed sign-ins over time:
```kql
SigninLogs
| where ResultType != 0
| summarize count() by bin(TimeGenerated, 1h)
| render timechart
```

Top targeted accounts:
```kql
SigninLogs
| where ResultType != 0
| summarize Failures = count() by UserPrincipalName
| top 10 by Failures
| render barchart
```

Sign-ins by country:
```kql
SigninLogs
| where ResultType == 0
| summarize count() by tostring(LocationDetails.countryOrRegion)
| render piechart
```

**Setup steps:**
1. Sentinel > Workbooks > Add workbook
2. Click "Edit"
3. Add query elements for each visualization
4. Add parameters (time range selector, user filter)
5. Save the workbook

---

## Workbook 2: Incident Management

**Purpose:** Track incident lifecycle and analyst performance.

**Queries used:**

Open incidents by severity:
```kql
SecurityIncident
| where Status != "Closed"
| summarize count() by Severity
| render piechart
```

Mean time to close:
```kql
SecurityIncident
| where Status == "Closed"
| extend TimeToClose = ClosedTime - CreatedTime
| summarize AvgCloseTime = avg(TimeToClose) by bin(CreatedTime, 1d)
| render timechart
```

---

## Built-in Workbook Templates

Sentinel comes with many pre-built workbook templates. Key ones for SC-200:

- **Microsoft Entra ID Sign-in Logs** (identity monitoring)
- **Microsoft 365 Security** (M365 activity overview)
- **Azure Activity** (resource changes)
- **Incident Overview** (SOC metrics)

To use: Sentinel > Workbooks > Templates > select and "Save"

---

## Template: Document New Workbooks

```markdown
## Workbook: [Name]

**Purpose:** [What this dashboard shows]

**Queries used:**
​```kql
// Query 1
​```

​```kql
// Query 2
​```

**Parameters:** [Time range, filters, etc.]
**Screenshot:** [Add dashboard screenshot here]
```
