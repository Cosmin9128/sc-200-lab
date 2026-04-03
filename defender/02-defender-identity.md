# Microsoft Defender for Identity

Monitoring and detecting identity-based threats in on-premises Active Directory.

---

## What It Does

Defender for Identity monitors Active Directory signals to detect:
- Reconnaissance (LDAP, DNS, SMB enumeration)
- Compromised credentials (brute force, pass-the-hash, pass-the-ticket)
- Lateral movement (overpass-the-hash, golden ticket, remote code execution)
- Domain dominance (DCSync, skeleton key, golden ticket)

**SC-200 exam focus:** Know the alert types, investigation workflow, and how it integrates with the Defender XDR portal.

---

## Key Alerts to Know

| Alert | MITRE Technique | Severity |
|-------|----------------|----------|
| Suspected brute force (Kerberos/NTLM) | T1110 | Medium |
| Suspected DCSync attack | T1003.006 | High |
| Suspected golden ticket usage | T1558.001 | High |
| Reconnaissance using DNS | T1046 | Medium |
| Suspected overpass-the-hash | T1550.002 | High |
| Honeytoken account activity | N/A | High |

---

## Investigation Workflow

1. Alert triggers in Defender XDR portal
2. Check the user timeline (what did this account do before/after?)
3. Check the device timeline (is the source device compromised?)
4. Check lateral movement paths (can this account reach sensitive targets?)
5. Decide: true positive (escalate) or false positive (tune)

---

## Notes

_Add lab observations here._
