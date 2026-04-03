# Microsoft Defender for Office 365

Email security and collaboration protection.

---

## Key Capabilities

- **Safe Attachments:** Detonates attachments in a sandbox before delivery
- **Safe Links:** Rewrites and scans URLs at time of click
- **Anti-phishing policies:** ML-based impersonation detection
- **Threat Explorer:** Interactive tool for investigating email threats
- **Automated Investigation and Response (AIR):** Auto-remediates email threats
- **Attack Simulation Training:** Phishing simulation for user awareness

---

## Threat Explorer Queries (SC-200 Must Know)

Find all emails from a specific sender:
1. security.microsoft.com > Email & collaboration > Explorer
2. Filter: Sender address = "suspicious@domain.com"
3. Review: delivery action, detection technology, recipients

Find all emails with malicious URLs:
1. Explorer > View: All email
2. Filter: URL threat = Phish or Malware
3. Review delivery status and take action (soft delete, hard delete)

---

## Key Tables for KQL

```kql
EmailEvents
| where TimeGenerated > ago(7d)
| where DetectionMethods != ""
| summarize count() by DetectionMethods
| sort by count_ desc
```

```kql
EmailAttachmentInfo
| where TimeGenerated > ago(7d)
| where ThreatTypes != ""
| summarize count() by ThreatTypes, FileName
| sort by count_ desc
```

---

## Notes

_Add lab observations here._
