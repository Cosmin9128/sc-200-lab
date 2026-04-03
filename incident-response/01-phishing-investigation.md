# Incident Response: Phishing Investigation

End-to-end playbook for investigating a reported phishing email.

---

## Scenario

A user reports receiving a suspicious email asking them to verify their credentials by clicking a link. The email appeared to come from IT support.

## Step 1: Triage (5 minutes)

**Gather initial information:**
- Who reported it?
- Did they click the link?
- Did they enter credentials?
- Forward the original email as attachment for header analysis

**Initial severity assessment:**
- No click: Low (block sender, purge email)
- Clicked but no credentials entered: Medium (check for drive-by download)
- Credentials entered: High (immediate account remediation)

## Step 2: Scope Assessment (15 minutes)

**How many users received this email?**
```kql
EmailEvents
| where SenderFromAddress == "suspicious-sender@domain.com"
    or Subject == "Verify Your Account - IT Support"
| summarize
    RecipientCount = dcount(RecipientEmailAddress),
    Recipients = make_set(RecipientEmailAddress),
    DeliveredCount = countif(DeliveryAction == "Delivered")
```

**Who clicked the link?**
```kql
UrlClickEvents
| where Url contains "phishing-domain.com"
| project TimeGenerated, AccountUpn, Url, ActionType, NetworkMessageId
```

## Step 3: Containment (immediate)

If credentials were entered:
1. Reset the user's password
2. Revoke all active sessions (Microsoft Entra ID > Users > Revoke sessions)
3. Enable MFA if not already enabled
4. Check for inbox rules created after the click
5. Check for OAuth app consents after the click

For all recipients:
1. Purge the phishing email from all mailboxes (Threat Explorer > select emails > Soft delete)
2. Block the sender domain
3. Block the phishing URL (Tenant Allow/Block List)

## Step 4: Investigation (30-60 minutes)

**Check for post-compromise activity:**
```kql
let compromisedUser = "user@domain.com";
let compromiseTime = datetime(2026-04-03T10:00:00Z);
union SigninLogs, OfficeActivity, AuditLogs
| where TimeGenerated > compromiseTime
| where UserPrincipalName == compromisedUser or UserId == compromisedUser
| project TimeGenerated, Activity = coalesce(OperationName, Operation), Source = $table, IPAddress
| sort by TimeGenerated asc
```

**Check for inbox rule creation:**
```kql
OfficeActivity
| where UserId == "user@domain.com"
| where Operation in ("New-InboxRule", "Set-InboxRule")
| project TimeGenerated, Operation, Parameters
```

## Step 5: Remediation

- Remove any malicious inbox rules
- Revoke any suspicious OAuth app consents
- Scan the user's device if they downloaded anything
- Document all findings in the Sentinel incident

## Step 6: Lessons Learned

- Was the email caught by existing policies? If not, why?
- Should we create a new analytics rule for this pattern?
- Do users need additional phishing awareness training?
- Document the full timeline in the incident for future reference

---

## Notes

_Add your investigation results and screenshots here._
