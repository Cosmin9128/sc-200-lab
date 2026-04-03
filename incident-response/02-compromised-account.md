# Incident Response: Compromised Account

---

## Scenario

Sentinel generates a "Impossible travel" alert. A user signed in from Romania and 10 minutes later from Brazil.

## Playbook

### 1. Triage
- Verify both sign-ins are successful (ResultType == 0)
- Check if the user has a VPN (could be false positive)
- Check if the user is currently traveling

### 2. Immediate Containment
- Disable the account (Microsoft Entra ID > Users > Block sign-in)
- Revoke all sessions
- Reset password

### 3. Investigation
```kql
let user = "user@domain.com";
let alertTime = datetime(2026-04-03T12:00:00Z);
SigninLogs
| where UserPrincipalName == user
| where TimeGenerated between ((alertTime - 24h) .. (alertTime + 24h))
| project TimeGenerated, ResultType, IPAddress, Location = LocationDetails.city, AppDisplayName, DeviceDetail
| sort by TimeGenerated asc
```

**Check what the attacker did:**
```kql
let user = "user@domain.com";
let compromiseTime = datetime(2026-04-03T12:00:00Z);
OfficeActivity
| where UserId == user
| where TimeGenerated > compromiseTime
| project TimeGenerated, Operation, OfficeObjectId, ClientIP
| sort by TimeGenerated asc
```

### 4. Determine Impact
- Were emails read or forwarded?
- Were files accessed or downloaded?
- Were inbox rules created?
- Were OAuth apps consented to?
- Was the account used to send phishing emails?

### 5. Remediation
- Remove malicious inbox rules
- Revoke malicious OAuth consents
- Re-enable account with new password + MFA enforced
- Notify user and their manager
- Close incident with full documentation

---

# Incident Response: Malware Outbreak

---

## Scenario

Defender for Endpoint generates multiple alerts for the same malware hash across several devices within 30 minutes.

## Playbook

### 1. Triage
- How many devices are affected?
- What is the malware classification?
- Was it blocked or did it execute?

```kql
AlertEvidence
| where TimeGenerated > ago(1h)
| where ThreatFamily == "MalwareName"
| summarize AffectedDevices = dcount(DeviceName), Devices = make_set(DeviceName) by ThreatFamily
```

### 2. Immediate Containment
- Isolate affected devices from the network (Defender portal > Device page > Isolate device)
- Block the malware hash across the organization (Indicators > File hash > Block)

### 3. Investigation
**How did the malware arrive?**
```kql
DeviceFileEvents
| where SHA256 == "malware_hash_here"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
| take 1
```

**What did the malware do after execution?**
```kql
let malwareTime = datetime(2026-04-03T14:00:00Z);
let affectedDevice = "DEVICE-01";
DeviceProcessEvents
| where DeviceName == affectedDevice
| where TimeGenerated between (malwareTime .. (malwareTime + 1h))
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```

### 4. Remediation
- Run full antivirus scan on isolated devices
- Remove malware artifacts
- Check for persistence mechanisms
- Un-isolate devices after cleanup confirmed
- Update email filtering if malware arrived via email

### 5. Post-Incident
- Was the malware a known threat? Check threat intelligence
- Update detection rules if existing rules missed it
- Brief affected users and management

---

## Notes

_Add your investigation results and screenshots here._
