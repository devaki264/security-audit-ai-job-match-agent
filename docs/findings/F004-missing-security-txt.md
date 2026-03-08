# F004 — Missing security.txt (RFC 9116)

**Date Discovered:** March 2026  
**Discovered By:** Devakinandan Palla  
**Phase:** 3 — Reconnaissance  
**Tool Used:** recon.py (custom script)  

---

## Summary

The application does not provide a `/.well-known/security.txt` file as defined by RFC 9116. This file is the industry standard method for communicating security contact information to researchers and analysts who discover vulnerabilities. Its absence means there is no official channel for responsible disclosure.

---

## Severity

| Property | Value |
|----------|-------|
| **Severity** | Informational |
| **CVSS v3.1 Score** | 0.0 |
| **OWASP Category** | A05:2021 — Security Misconfiguration |
| **Standard** | RFC 9116 |

---

## Affected Asset

```
https://ai-job-match-agent-686566480080.us-central1.run.app/.well-known/security.txt
```

---

## Evidence

```
  404  /.well-known/security.txt  [MISSING] - Security contact (RFC 9116)
```

Confirmed via direct HTTP GET request returning 404.

---

## Impact

Without a `security.txt`:
- Security researchers have no official channel to report vulnerabilities
- Discovered vulnerabilities may go unreported or be disclosed publicly without warning
- The application appears immature from a security posture perspective
- Bug bounty programs and responsible disclosure programs rely on this file

---

## Remediation

Create the file at `public/.well-known/security.txt` in the Next.js project:

```
Contact: mailto:devakinandanpp@gmail.com
Expires: 2027-03-07T00:00:00.000Z
Preferred-Languages: en
Canonical: https://ai-job-match-agent-686566480080.us-central1.run.app/.well-known/security.txt
Policy: https://ai-job-match-agent-686566480080.us-central1.run.app/security-policy
```

In Next.js, placing this file at `public/.well-known/security.txt` will serve it automatically at the correct path.

You can also generate one at: https://securitytxt.org

---

## Remediation Status

- [x] Identified
- [x] Fix implemented
- [x] Fix verified

---

## References

- [RFC 9116 — security.txt standard](https://www.rfc-editor.org/rfc/rfc9116)
- [securitytxt.org generator](https://securitytxt.org)

---

*Finding documented as part of self-directed security assessment of AI Job Match Agent*