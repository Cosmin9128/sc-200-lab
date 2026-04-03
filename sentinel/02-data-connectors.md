# Microsoft Sentinel: Data Connectors

Configuration guide for connecting data sources to Microsoft Sentinel.

---

## Priority Connectors for SC-200 Lab

| Connector | Data Source | SC-200 Relevance |
|-----------|------------|-------------------|
| Microsoft 365 Defender | Alerts, incidents, raw data from all Defender products | Critical - 25-30% of exam |
| Microsoft Entra ID | Sign-in logs, audit logs | Critical - identity-based queries |
| Microsoft Entra ID Protection | Risk events, risky users | High |
| Office 365 | Exchange, SharePoint, Teams activity | High |
| Microsoft Defender for Cloud | Cloud security alerts | High - 15-20% of exam |
| Azure Activity | Azure resource operations | Medium |

---

## Connector: Microsoft 365 Defender

**What it ingests:** Alerts, incidents, and raw event data from Defender for Endpoint, Defender for Office 365, Defender for Identity, Defender for Cloud Apps.

**Setup steps:**
1. Sentinel > Data Connectors > search "Microsoft 365 Defender"
2. Click "Open connector page"
3. Click "Connect incidents & alerts"
4. Under "Connect events," enable tables you need:
   - DeviceProcessEvents
   - DeviceNetworkEvents
   - DeviceFileEvents
   - DeviceLogonEvents
   - EmailEvents
   - EmailAttachmentInfo
5. Click "Apply Changes"

**Validation query:**
```kql
SecurityIncident
| where TimeGenerated > ago(1h)
| take 5
```

---

## Connector: Microsoft Entra ID (Azure AD)

**What it ingests:** Sign-in logs (interactive, non-interactive, service principal), audit logs.

**Setup steps:**
1. Sentinel > Data Connectors > search "Microsoft Entra ID"
2. Click "Open connector page"
3. Enable:
   - Sign-in logs
   - Audit logs
   - Non-interactive user sign-in logs
   - Service principal sign-in logs
   - Provisioning logs
4. Click "Apply Changes"

**Validation query:**
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| summarize count() by ResultType
```

---

## Connector: Office 365

**What it ingests:** Exchange mail flow, SharePoint file operations, Teams events.

**Setup steps:**
1. Sentinel > Data Connectors > search "Office 365"
2. Click "Open connector page"
3. Enable: Exchange, SharePoint, Teams
4. Click "Apply Changes"

**Validation query:**
```kql
OfficeActivity
| where TimeGenerated > ago(1h)
| summarize count() by OfficeWorkload
```

---

## Template: Document New Connectors

```markdown
## Connector: [Name]

**What it ingests:** [Description]

**Setup steps:**
1. [Step by step]

**Validation query:**
​```kql
// Query to verify data is flowing
​```

**Notes:** [Any issues encountered, tips]
**Screenshot:** [Add screenshot here]
```
