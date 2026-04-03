# Threat Hunting: Credential Access (TA0006)

---

## Scenario: Password Spray Followed by Successful Login (T1110.003)

**Hypothesis:** Attacker performed a password spray and successfully compromised at least one account.

**Hunt query:**
```kql
let sprayIPs = SigninLogs
    | where TimeGenerated > ago(24h)
    | where ResultType == "50126"
    | summarize TargetCount = dcount(UserPrincipalName) by IPAddress
    | where TargetCount > 10
    | project IPAddress;
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| where IPAddress in (sprayIPs)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, Location = LocationDetails.countryOrRegion
```

**Response:** Immediately disable the compromised account, revoke sessions, check for post-compromise activity.

---

## Scenario: Token Theft via AiTM Phishing (T1557)

**Hypothesis:** Attacker stole session tokens using an adversary-in-the-middle phishing kit.

**Hunt query:**
```kql
AADSignInEventsBeta
| where TimeGenerated > ago(7d)
| where ErrorCode == 0
| where IsInteractive == true
| where SessionId != ""
| summarize
    IPCount = dcount(IPAddress),
    IPs = make_set(IPAddress),
    DeviceCount = dcount(DeviceName)
    by SessionId, AccountUpn
| where IPCount > 1
```

**What to look for:** Same session ID used from multiple IPs indicates the session token was stolen and replayed from a different location.

---

# Threat Hunting: Lateral Movement (TA0008)

---

## Scenario: Remote Desktop Protocol Abuse (T1021.001)

**Hypothesis:** Attacker is using RDP to move laterally between internal systems.

**Hunt query:**
```kql
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemotePort == 3389
| where ActionType == "ConnectionSuccess"
| summarize
    ConnectionCount = count(),
    UniqueTargets = dcount(RemoteIP),
    Targets = make_set(RemoteIP, 10)
    by DeviceName, InitiatingProcessAccountName
| where UniqueTargets > 3
| sort by UniqueTargets desc
```

**Red flags:** Single user/device connecting to many internal systems via RDP, especially outside business hours. Focus on accounts that don't typically use RDP.

---

## Scenario: PsExec or Remote Service Execution (T1021.002)

**Hypothesis:** Attacker is using PsExec or similar tools for remote execution.

**Hunt query:**
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("psexec.exe", "psexec64.exe", "paexec.exe")
    or (FileName =~ "cmd.exe" and InitiatingProcessFileName =~ "services.exe")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated desc
```

**Red flags:** PsExec usage from non-IT accounts, execution targeting multiple devices in sequence, commands that download or execute additional payloads.

---

## Notes

_Add your hunting results and observations here._
