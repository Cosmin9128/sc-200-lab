# Threat Hunting: Persistence (TA0003)

Hunting scenarios for detecting persistence mechanisms.

---

## Scenario: Scheduled Task Creation (T1053.005)

**Hypothesis:** Attacker created a scheduled task to maintain persistence on a compromised endpoint.

**Hunt query:**
```kql
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated desc
```

**Red flags:** Tasks running executables from temp directories, tasks created by unusual parent processes, tasks set to run at login or on a recurring schedule with encoded commands.

---

## Scenario: Registry Run Key Modification (T1547.001)

**Hypothesis:** Attacker added a registry run key to execute malware at every login.

**Hunt query:**
```kql
DeviceRegistryEvents
| where TimeGenerated > ago(7d)
| where RegistryKey has_any ("CurrentVersion\\Run", "CurrentVersion\\RunOnce")
| where ActionType == "RegistryValueSet"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessAccountName
| sort by TimeGenerated desc
```

**Red flags:** Values pointing to executables in %TEMP%, %APPDATA%, or other unusual locations. Processes written by cmd.exe or powershell.exe.

---

## Scenario: New Service Installation (T1543.003)

**Hypothesis:** Attacker installed a malicious Windows service for persistence.

**Hunt query:**
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 7045
| project TimeGenerated, Computer, ServiceName = EventData.ServiceName, ServicePath = EventData.ImagePath, AccountName = EventData.AccountName
| sort by TimeGenerated desc
```

**Red flags:** Services with random names, services running from unusual paths, services running as SYSTEM that were not installed by known software.

---

## Notes

_Add your hunting results and observations here._
