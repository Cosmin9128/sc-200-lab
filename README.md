# SC-200 Lab: Microsoft Security Operations Analyst

Hands-on lab documentation and practical study guide for the **SC-200 Microsoft Security Operations Analyst** certification exam.

## About This Repository

This repo documents my journey preparing for the SC-200 exam through practical, hands-on exercises in the Microsoft Security stack. Every query, configuration, and scenario here was tested in a real environment (M365 E5 trial + Azure Sentinel).

The goal: not just pass the exam, but build real SOC Analyst skills that translate directly to the job.

## Repository Structure

```
sc-200-lab/
├── kql-queries/           # KQL queries with explanations and use cases
│   ├── 01-fundamentals.md
│   ├── 02-threat-hunting.md
│   ├── 03-incident-investigation.md
│   └── 04-advanced-patterns.md
│
├── sentinel/              # Microsoft Sentinel setup and configuration
│   ├── 01-workspace-setup.md
│   ├── 02-data-connectors.md
│   ├── 03-analytics-rules.md
│   ├── 04-workbooks.md
│   └── 05-playbooks-soar.md
│
├── defender/              # Microsoft Defender XDR documentation
│   ├── 01-defender-endpoint.md
│   ├── 02-defender-identity.md
│   ├── 03-defender-cloud-apps.md
│   └── 04-defender-office365.md
│
├── hunting/               # Threat hunting scenarios mapped to MITRE ATT&CK
│   ├── 01-initial-access.md
│   ├── 02-persistence.md
│   ├── 03-credential-access.md
│   └── 04-lateral-movement.md
│
├── incident-response/     # End-to-end IR scenarios
│   ├── 01-phishing-investigation.md
│   ├── 02-compromised-account.md
│   ├── 03-malware-outbreak.md
│   └── 04-data-exfiltration.md
│
└── study-notes/           # SC-200 exam prep notes and tips
    ├── exam-domains.md
    └── practice-test-insights.md
```

## SC-200 Exam Domains Covered

| Domain | Weight | Lab Coverage |
|--------|--------|-------------|
| Mitigate threats using Microsoft Defender XDR | 25-30% | `defender/` |
| Mitigate threats using Microsoft Sentinel | 50-55% | `sentinel/`, `kql-queries/`, `hunting/` |
| Mitigate threats using Microsoft Defender for Cloud | 15-20% | `defender/04-defender-cloud.md` |

## Tools and Environment

- Microsoft 365 E5 Trial (27 days)
- Microsoft Sentinel (Azure)
- Microsoft Defender XDR Portal
- Azure Data Explorer (KQL practice)
- KQL for Cybersecurity course (Christopher Nett, Udemy)
- Tutorial Dojo SC-200 practice exams

## Study Timeline

**8-week plan: April 1 to May 25, 2026**

| Week | Focus | Repo Section |
|------|-------|-------------|
| 1-2 | KQL Fundamentals | `kql-queries/01-fundamentals.md` |
| 3 | KQL for Threat Hunting | `kql-queries/02-threat-hunting.md` |
| 4 | Microsoft Sentinel | `sentinel/` |
| 5 | Defender XDR | `defender/` |
| 6 | Threat Hunting + MITRE | `hunting/` |
| 7 | Incident Response | `incident-response/` |
| 8 | Review + Exam | `study-notes/` |

## Certifications Context

- CompTIA Security+ (completed)
- ISC2 CC (completed)
- SC-900: Microsoft Security Fundamentals (completed)
- AZ-900: Azure Fundamentals (completed)
- **SC-200: Target exam date May 2026**

## Author

QA Automation Engineer transitioning into cybersecurity, targeting SOC Analyst roles. 9 years of testing experience bringing structured, detail-oriented thinking to security operations.

## License

This project is for educational purposes. Feel free to use and adapt for your own SC-200 preparation.
