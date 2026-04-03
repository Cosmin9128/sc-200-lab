# Microsoft Defender for Endpoint

Configuration and usage guide for Defender for Endpoint in the SC-200 lab.

---

## Key Capabilities (SC-200 Exam Focus)

- Endpoint Detection and Response (EDR)
- Automated Investigation and Response (AIR)
- Threat and Vulnerability Management (TVM)
- Attack Surface Reduction (ASR)
- Device inventory and health monitoring

---

## Onboarding Devices

**M365 E5 trial includes Defender for Endpoint Plan 2.**

Methods for onboarding:
- Local script (for lab/testing, download from security.microsoft.com)
- Group Policy
- Microsoft Intune
- Configuration Manager

For the lab, use the local script method:
1. Go to security.microsoft.com > Settings > Endpoints > Onboarding
2. Select "Local Script" as deployment method
3. Download the onboarding package
4. Run the script on your test device as Administrator

**Validation:**
- Device should appear in Device Inventory within 5-10 minutes
- Run: `sc query sense` in CMD to verify the service is running

---

## Key Portal Sections

**Incidents & Alerts:** Correlated alerts grouped into incidents. This is where SOC analysts start triage.

**Device Inventory:** All onboarded devices with health status, OS, risk level.

**Advanced Hunting:** KQL queries against Defender tables (DeviceProcessEvents, DeviceNetworkEvents, etc.)

**Threat & Vulnerability Management:** Software inventory, vulnerability assessment, security recommendations.

---

## Important Defender Tables for KQL

| Table | Contains |
|-------|---------|
| DeviceProcessEvents | Process creation events |
| DeviceNetworkEvents | Network connections |
| DeviceFileEvents | File creation, modification, deletion |
| DeviceLogonEvents | Login events on endpoints |
| DeviceRegistryEvents | Registry changes |
| DeviceImageLoadEvents | DLL loading events |
| AlertInfo | Alert metadata |
| AlertEvidence | Evidence linked to alerts |

---

## Response Actions

Actions you can take on a device from the portal:
- **Isolate device** (cut network, keep Defender connection)
- **Run antivirus scan**
- **Collect investigation package** (forensic data bundle)
- **Restrict app execution** (only Microsoft-signed binaries run)
- **Initiate automated investigation**
- **Initiate Live Response** (remote shell)

Actions on a file:
- **Stop and quarantine**
- **Add indicator** (block across org)
- **Download file** (for analysis)

---

## Notes

_Add your observations, screenshots, and lab results here as you work through the Defender portal._
