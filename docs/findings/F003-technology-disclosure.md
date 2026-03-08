# F003 — Technology Stack Disclosure via Response Header

**Date Discovered:** March 2026  
**Discovered By:** Devakinandan Palla  
**Phase:** 3 — Reconnaissance  
**Tool Used:** recon.py (custom script)  

---

## Summary

The application returns an `x-powered-by: Next.js` header in all HTTP responses. This reveals the underlying framework to any observer, enabling attackers to target known Next.js vulnerabilities without needing to fingerprint the stack manually.

---

## Severity

| Property | Value |
|----------|-------|
| **Severity** | Informational |
| **CVSS v3.1 Score** | 0.0 (no direct exploitability) |
| **OWASP Category** | A05:2021 — Security Misconfiguration |
| **CWE** | CWE-200: Exposure of Sensitive Information |

---

## Affected Asset

```
https://ai-job-match-agent-686566480080.us-central1.run.app (all routes)
```

---

## Evidence

```
--- All Response Headers ---
  x-powered-by: Next.js
  x-nextjs-cache: HIT
  x-nextjs-prerender: 1, 1
  x-nextjs-stale-time: 300
  server: Google Frontend
```

Multiple Next.js-specific headers are returned, making framework identification trivial.

---

## Impact

While this finding alone is not directly exploitable, it lowers the barrier for targeted attacks:

- Attacker immediately knows the tech stack without scanning
- Can search for known CVEs specific to the Next.js version in use
- Additional `x-nextjs-*` headers reveal internal caching and rendering behavior
- Combined with other findings, accelerates attack chain development

**Defense in depth principle:** The less information an attacker has, the more work they must do. Removing these headers is a low-cost improvement.

---

## Remediation

Remove the `x-powered-by` header in `next.config.js`:

```javascript
// next.config.js
module.exports = {
  poweredByHeader: false,  // removes x-powered-by: Next.js
}
```

Note: The `x-nextjs-cache` and `x-nextjs-prerender` headers are harder to remove as they are set by Next.js internals, but `poweredByHeader: false` handles the most identifiable one.

---

## Remediation Status

- [x] Identified
- [x] Fix implemented
- [x] Fix verified

---

## References

- [Next.js poweredByHeader config](https://nextjs.org/docs/api-reference/next.config.js/disabling-x-powered-by)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

---

*Finding documented as part of self-directed security assessment of AI Job Match Agent*