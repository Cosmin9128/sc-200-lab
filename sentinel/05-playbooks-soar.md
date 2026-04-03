# Microsoft Sentinel: Playbooks (SOAR)

Automated response playbooks using Logic Apps for Security Orchestration, Automation, and Response.

---

## What Are Playbooks?

Playbooks are automated workflows triggered by Sentinel incidents or alerts. They use Azure Logic Apps to perform actions like sending notifications, blocking users, or enriching incidents with threat intelligence.

**SC-200 exam focus:** Know how to create playbooks, trigger them from automation rules, and understand common SOAR scenarios.

---

## Playbook 1: Auto-Enrich Incident with User Details

**Trigger:** When a Sentinel incident is created
**Purpose:** Automatically add user details (job title, department, manager) to the incident for faster triage.

**Logic App flow:**
1. Trigger: Microsoft Sentinel incident
2. Get incident entities (extract Account entity)
3. For each account entity:
   - Get user details from Microsoft Entra ID
   - Add comment to incident with: display name, job title, department, manager, last sign-in
4. Update incident tags with department name

**Setup steps:**
1. Sentinel > Automation > Create > Playbook with incident trigger
2. Name: "Enrich-Incident-UserDetails"
3. In Logic App Designer, add steps:
   - "Entities - Get Accounts" (Sentinel connector)
   - "Get user" (Microsoft Entra ID connector)
   - "Add comment to incident" (Sentinel connector)
4. Save and authorize connectors
5. Create an Automation Rule to trigger this playbook on new incidents

---

## Playbook 2: Notify SOC Team on High Severity Incident

**Trigger:** When a Sentinel incident is created (filtered to High/Critical severity)
**Purpose:** Send immediate notification to the SOC team channel.

**Logic App flow:**
1. Trigger: Microsoft Sentinel incident
2. Condition: Severity equals "High" or "Critical"
3. If true:
   - Post message to Teams channel with incident details
   - Send email to SOC distribution list
4. Add comment to incident confirming notification sent

---

## Playbook 3: Block Compromised User

**Trigger:** Manual (run from incident)
**Purpose:** Disable a compromised user account and revoke all sessions.

**Logic App flow:**
1. Trigger: Microsoft Sentinel incident (manual)
2. Get incident entities (extract Account)
3. Disable user account (Microsoft Entra ID connector)
4. Revoke sign-in sessions (Microsoft Entra ID connector)
5. Add comment to incident documenting the action
6. Update incident status to "Active" and assign to analyst

**Important:** This playbook should be manual, not automatic, to avoid disabling legitimate users by mistake.

---

## Automation Rules vs. Playbooks

| Feature | Automation Rules | Playbooks |
|---------|-----------------|-----------|
| What they do | Triage and manage incidents | Execute complex workflows |
| Technology | Built into Sentinel | Azure Logic Apps |
| Complexity | Simple (assign, tag, change severity) | Complex (API calls, conditions, loops) |
| Cost | Free | Logic Apps pricing applies |
| SC-200 exam | Must know | Must know |

**Common automation rule actions:**
- Auto-assign incidents to analysts
- Change severity based on entities
- Add tags
- Run a playbook
- Close known false positives

---

## Template: Document New Playbooks

```markdown
## Playbook: [Name]

**Trigger:** [Incident / Alert / Manual]
**Purpose:** [What this playbook does]

**Logic App flow:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Connectors used:** [List of Logic App connectors]
**Setup steps:** [Detailed steps with screenshots]
**Testing:** [How to test this playbook]
```
