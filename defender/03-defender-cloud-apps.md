# Microsoft Defender for Cloud Apps

Cloud Access Security Broker (CASB) for monitoring and controlling cloud app usage.

---

## Key Capabilities

- **Shadow IT discovery:** Find unsanctioned cloud apps in your environment
- **App governance:** Control which apps can access your data
- **Threat protection:** Detect anomalous user behavior in cloud apps
- **Information protection:** DLP policies for cloud apps
- **Conditional Access App Control:** Real-time session monitoring and control

---

## Important Policies for SC-200

| Policy Type | Example | Purpose |
|------------|---------|---------|
| Activity policy | Mass download by single user | Detect data exfiltration |
| Anomaly detection | Impossible travel | Detect compromised accounts |
| File policy | Shared externally with sensitive labels | Prevent data leaks |
| Session policy | Block download of sensitive files | Real-time DLP |

---

## Key Tables for KQL

```kql
CloudAppEvents
| where TimeGenerated > ago(24h)
| summarize count() by ActionType
| sort by count_ desc
| take 20
```

---

## Notes

_Add lab observations here._
