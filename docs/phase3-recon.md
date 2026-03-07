# Phase 3: Reconnaissance

**Project:** Bug Bounty Style Security Assessment — AI Job Match Agent  
**Author:** Devakinandan Palla  
**Date:** March 2026  
**Phase:** 3 of 7  

---

## Objective

Gather as much information as possible about the target before active testing. Recon identifies the attack surface, confirms the tech stack, and surfaces low-hanging fruit like exposed files or missing security headers.

---

## Recon Categories

| Category | Method | Tool |
|----------|--------|------|
| HTTP Security Headers | Inspect response headers | `recon.py`, Burp Suite |
| SSL/TLS Certificate | Check cert validity, SANs | `recon.py` |
| Endpoint Discovery | Probe common paths | `recon.py`, ffuf |
| Information Disclosure | Check for exposed config files | `recon.py` |
| Cookie Security | Inspect cookie flags | `recon.py`, Browser DevTools |
| CORS Configuration | Test origin reflection | `recon.py` |
| Tech Stack Fingerprinting | Identify frameworks and versions | Browser DevTools, Wappalyzer |
| JavaScript Analysis | Find exposed API keys or endpoints | Browser DevTools |

---

## Running the Recon Script

```bash
# From the project root
pip install requests
python tools/recon.py
```

Output is saved to `reports/recon-output.txt` and printed to console.

---

## Manual Recon Steps

### 1. Browser DevTools (F12)

Open your app in Chrome/Firefox with DevTools open:

- **Network tab** — inspect every request/response, look for:
  - API keys in request headers
  - Sensitive data in responses
  - Internal URLs or endpoints
- **Application tab** → Cookies — check Secure, HttpOnly, SameSite flags
- **Sources tab** — browse JavaScript files for:
  - Hardcoded API keys
  - Internal endpoint paths
  - Environment variable names

### 2. Wappalyzer Extension

Install Wappalyzer (free browser extension) and visit your app. It fingerprints:
- Framework (Next.js version)
- Hosting provider
- Analytics tools
- CDN in use

### 3. robots.txt and sitemap.xml

Visit these manually:
```
https://ai-job-match-agent-686566480080.us-central1.run.app/robots.txt
https://ai-job-match-agent-686566480080.us-central1.run.app/sitemap.xml
```

Anything listed in `robots.txt` as `Disallow` is interesting — it tells you what the developer didn't want crawled.

### 4. JavaScript File Analysis

In Browser DevTools → Sources, look for files like:
- `_next/static/chunks/pages/dashboard.js`
- Any file containing `NEXT_PUBLIC_` variables
- API route definitions

Search (Ctrl+F) for:
- `api_key`
- `secret`
- `token`
- `password`
- `supabase`
- `NEXT_PUBLIC`

### 5. Google Dorking Your Own Domain

Search Google for:
```
site:ai-job-match-agent-686566480080.us-central1.run.app
```

This shows what Google has indexed — sometimes reveals unintended pages.

---

## What to Look For

### High Value Findings
- Missing `Strict-Transport-Security` header
- Missing `Content-Security-Policy` header
- Cookies without `Secure` or `HttpOnly` flags
- CORS misconfiguration (reflects arbitrary origins)
- Exposed `.env` or config files
- Verbose error messages with stack traces

### Medium Value Findings
- Missing `X-Frame-Options` (clickjacking risk)
- Missing `X-Content-Type-Options`
- No `robots.txt` or `security.txt`
- Server version disclosure in headers

---

## Recording Your Findings

For each issue discovered in recon, create a file in `docs/findings/` using this naming convention:

```
F001-missing-security-headers.md
F002-cors-misconfiguration.md
F003-exposed-endpoint.md
```

We'll fill these out fully in Phase 5.

---

## Next Phase

→ **[Phase 4: OWASP Top 10 Testing](phase4-owasp.md)**  
Active testing against all 10 OWASP vulnerability categories using Burp Suite and custom scripts.

---

*Last updated: March 2026*