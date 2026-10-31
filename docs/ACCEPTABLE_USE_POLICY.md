# 📜 ARGOLOCK NET — Acceptable Use Policy (AUP)

**Effective Date**: October 31, 2026  
**Version**: 1.0  
**Scope**: All operators, analysts, administrators, and automated integrations using ARGOLOCK NET.

---

## 1. Core Principles

ARGOLOCK NET is designed to empower defensive engineering and authorized ethical penetration testing. All operations conducted using ARGOLOCK must adhere to the principles of **authorization**, **safe minimum-impact**, and **transparency**.

---

## 2. Permitted Testing Activities

You may utilize ARGOLOCK for the following activities, provided written authorization is stored:
- **Authorized Vulnerability Assessments**: Scanning web applications, microservices, and network boundaries owned by your organization.
- **Controlled Exploitation Proofs**: Executing minimum-impact, non-destructive proofs of concept (PoCs) strictly to verify reproducibility (e.g. confirming differential responses for SQLi or reflected parameter contexts).
- **Bug Bounty Programs**: Assessing targets explicitly permitted under published bug bounty guidelines within documented scope limits and rate ceilings.
- **Remediation Re-testing**: Re-running automated probes using the original test method to verify that a vulnerability has been patched.

---

## 3. Strictly Prohibited Targets

The Platform shall NOT be directed at:
1. **Critical National Infrastructure**: Energy grids, healthcare systems, water facilities, transportation networks, or emergency services.
2. **Third-Party Shared Services**: Cloud multi-tenant planes, authentication providers (e.g. Google Accounts, Auth0, Okta), payment gateways, or third-party web chats.
3. **Internal Cloud Metadata Endpoints**: `169.254.169.254` or internal instance identity endpoints.
4. **Unowned Systems**: Any domain, host, or IP address for which you do not possess verified ownership credentials or written legal authorization.

---

## 4. Strictly Prohibited Actions

The following actions are strictly barred by policy and technical control gates:
- **Destructive Operations**: Dropping databases or tables, truncating records, erasing files, modifying production records, or executing fuzzing designed to induce system crashes.
- **Denial of Service (DoS)**: Flooding targets with excessive traffic, opening connection exhaustion pools, or triggering resource starvation.
- **Data Exfiltration Beyond Proof**: Extracting bulk customer PII, financial information, or intellectual property beyond the minimum data required to demonstrate technical impact.
- **Unauthorized Lateral Movement**: Attempting to pivot from an authorized target into out-of-scope adjacent networks.

---

## 5. Safe Minimum-Impact Standard

Whenever executing validation probes or controlled exploitation:
1. Prefer read-only verification (e.g., querying `@@version` or displaying non-destructive headers) over data-modifying queries.
2. Keep probe concurrency at or below configured thresholds.
3. Immediately cease testing and notify system administrators if an unintended system impairment or service degradation is observed.

---

## 6. Coordinated Vulnerability Disclosure & Reporting

All security issues identified via the Platform must be handled in accordance with responsible disclosure principles:
- Inform affected system owners promptly through secure, encrypted communication channels.
- Provide clear, reproducible technical steps without exaggerating risk scores or claiming unverified impacts.
- Do not publicly disclose vulnerabilities until reasonable remediation windows have elapsed.
