# F002 — Missing Security Headers

**Date Discovered:** March 2026  
**Discovered By:** Devakinandan Palla  
**Phase:** 3 — Reconnaissance  
**Tool Used:** recon.py (custom script)  

---

## Summary

7 out of 8 critical HTTP security headers are absent from all application responses. Security headers are a first line of defense that instruct browsers how to handle content, prevent common attacks like XSS and clickjacking, and enforce secure transport. Their absence leaves users exposed to several well-documented attack vectors.

---

## Severity

| Property | Value |
|----------|-------|
| **Severity** | Medium |
| **CVSS v3.1 Score** | 5.4 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| **OWASP Category** | A05:2021 — Security Misconfiguration |
| **CWE** | CWE-693: Protection Mechanism Failure |

---

## Affected Asset

```
https://ai-job-match-agent-686566480080.us-central1.run.app (all routes)
```

---

## Evidence

Running `python tools/recon.py` against the target produced the following output:

```
--- Security Header Analysis ---
  [MISSING]  Strict-Transport-Security
  [MISSING]  Content-Security-Policy
  [MISSING]  X-Frame-Options
  [MISSING]  X-Content-Type-Options
  [MISSING]  Referrer-Policy
  [MISSING]  Permissions-Policy
  [MISSING]  X-XSS-Protection

Summary: 1 present, 7 missing
```

Only `Cache-Control` was present. All security-relevant headers were absent.

---

## Missing Headers — Detail

| Header | Risk if Missing | Recommended Value |
|--------|----------------|-------------------|
| `Strict-Transport-Security` | Users can be downgraded to HTTP via MITM attacks | `max-age=31536000; includeSubDomains` |
| `Content-Security-Policy` | No XSS protection, allows inline scripts and arbitrary resource loading | `default-src 'self'; script-src 'self'` |
| `X-Frame-Options` | App can be embedded in iframes enabling clickjacking attacks | `DENY` or `SAMEORIGIN` |
| `X-Content-Type-Options` | Browser may MIME-sniff responses leading to XSS | `nosniff` |
| `Referrer-Policy` | Full URL sent to third parties on navigation, leaking app paths | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | No restriction on browser features (camera, mic, geolocation) | `geolocation=(), microphone=(), camera=()` |
| `X-XSS-Protection` | Legacy browsers lack XSS filter activation | `1; mode=block` |

---

## Impact

Without these headers an attacker can potentially:
- Embed the app in a malicious iframe to perform clickjacking attacks (`X-Frame-Options` missing)
- Inject and execute malicious scripts via XSS with no browser-level mitigation (`Content-Security-Policy` missing)
- Intercept traffic via HTTP downgrade attacks (`Strict-Transport-Security` missing)
- Trick browsers into misinterpreting response content types (`X-Content-Type-Options` missing)

---

## Remediation

Add the following headers in `next.config.js`:

```javascript
// next.config.js
const securityHeaders = [
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
  { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'geolocation=(), microphone=(), camera=()' },
  { key: 'X-XSS-Protection', value: '1; mode=block' },
]

module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ]
  },
}
```

---

## Remediation Status

- [x] Identified
- [ ] Fix implemented
- [ ] Fix verified

---

## References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [Next.js Security Headers](https://nextjs.org/docs/advanced-features/security-headers)

---

*Finding documented as part of self-directed security assessment of AI Job Match Agent*