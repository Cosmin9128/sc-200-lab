# Threat Hunting: Initial Access (TA0001)

Hunting scenarios for detecting initial access techniques.

---

## Scenario: Phishing Link Clicked (T1566.002)

**Hypothesis:** An attacker sent a phishing email with a malicious link. One or more users clicked it.

**Hunt query:**
```kql
EmailEvents
| where TimeGenerated > ago(7d)
| where DeliveryAction == "Delivered"
| join kind=inner (
    EmailUrlInfo
    | where UrlLocation == "Body"
) on NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | where ActionType == "ClickAllowed"
) on Url
| project TimeGenerated, RecipientEmailAddress, SenderFromAddress, Subject, Url, UrlDomain
| sort by TimeGenerated desc
```

**What to look for:**
- URLs pointing to credential harvesting pages
- Domains registered recently (check whois)
- Multiple users clicking the same URL

**Response if confirmed:**
1. Block the URL across the organization
2. Check for successful sign-ins from unusual locations after the click
3. Reset passwords for users who entered credentials
4. Purge the email from all mailboxes

---

## Scenario: OAuth App Consent Phishing (T1566.002 + T1550.001)

**Hypothesis:** User was tricked into granting permissions to a malicious OAuth application.

**Hunt query:**
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend AppName = TargetResources[0].displayName
| extend Permissions = TargetResources[0].modifiedProperties
| project TimeGenerated, UserPrincipalName = InitiatedBy.user.userPrincipalName, AppName, Permissions
| sort by TimeGenerated desc
```

**Red flags:** Apps requesting Mail.Read, Files.ReadWrite, or full access permissions. Apps with generic names. Consent granted outside business hours.

---

## Template: Add New Hunting Scenarios

```markdown
## Scenario: [Name] ([MITRE Technique])

**Hypothesis:** [What you think happened]

**Hunt query:**
​```kql
// Query
​```

**What to look for:** [Indicators]
**Response if confirmed:** [Steps]
**Data requirements:** [Tables/connectors needed]
```
