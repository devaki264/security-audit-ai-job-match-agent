# Phase 2: Scope Definition

**Project:** Bug Bounty Style Security Assessment — AI Job Match Agent  
**Author:** Devakinandan Palla  
**Date:** March 2026  
**Phase:** 2 of 7  

---

## Target Application

| Property | Value |
|----------|-------|
| **Application Name** | AI Job Match Agent |
| **Base URL** | https://ai-job-match-agent-686566480080.us-central1.run.app |
| **Hosting** | Google Cloud Run (us-central1) |
| **Stack** | Next.js, Supabase (PostgreSQL + Auth + pgvector), Cloudflare Workers, Redis, Resend API |
| **Auth Provider** | Google OAuth 2.0 |

---

## In-Scope Targets

These are the assets I am authorized to test — I own and operate this application.

### Application Endpoints
| Endpoint | Description |
|----------|-------------|
| `https://ai-job-match-agent-686566480080.us-central1.run.app/` | Homepage / landing |
| `https://ai-job-match-agent-686566480080.us-central1.run.app/login` | Google OAuth login flow |
| `https://ai-job-match-agent-686566480080.us-central1.run.app/dashboard` | Authenticated user dashboard |
| `https://ai-job-match-agent-686566480080.us-central1.run.app/api/*` | All internal API routes |
| `https://ai-job-match-agent-686566480080.us-central1.run.app/auth/*` | Auth callback and session routes |

### Attack Surface Areas
- **Authentication & Session Management** — Google OAuth flow, cookie handling, JWT tokens
- **API Security** — All `/api/*` routes, input validation, authorization checks
- **Access Control** — Authenticated vs unauthenticated route protection
- **Security Headers** — HTTP response headers, CORS configuration
- **Rate Limiting** — Email alert endpoints, login endpoints, API endpoints
- **Data Exposure** — Error messages, stack traces, sensitive info in responses
- **Injection** — SQL injection via Supabase/pgvector queries, XSS in dashboard
- **SSRF** — Cloudflare Workers fetching external career pages

---

## Out-of-Scope Targets

The following are explicitly **not** tested — they are third-party infrastructure I do not own:

| Asset | Reason |
|-------|--------|
| `supabase.com` and Supabase infrastructure | Third-party provider |
| `accounts.google.com` | Google's OAuth servers |
| `api.resend.com` | Third-party email provider |
| `workers.cloudflare.com` | Cloudflare's infrastructure |
| `redis.io` / Redis Cloud infrastructure | Third-party provider |
| Any other user's data or accounts | Privacy / ethics boundary |

---

## Rules of Engagement

These rules mirror professional bug bounty program standards (e.g. HackerOne, Bugcrowd):

1. **No Denial of Service (DoS)** — No flood attacks, no intentional service disruption
2. **No automated aggressive scanning** against live production without rate limiting
3. **No accessing other users' data** — All testing done against my own test accounts only
4. **No destructive actions** — No deleting data, no modifying production records
5. **No social engineering** — Assessment is purely technical
6. **Test accounts only** — Create dedicated test accounts for all auth testing, never use real user sessions
7. **Document before exploiting** — Screenshot and record every finding before attempting to exploit further

---

## Testing Accounts

| Account | Purpose |
|---------|---------|
| `security-test-1@gmail.com` | Primary test account for authenticated testing |
| `security-test-2@gmail.com` | Secondary account for access control / privilege testing |

> ⚠️ Never use real user accounts for security testing. Create dedicated Google accounts for this purpose.

---

## Severity Classification

Findings will be scored using **CVSS v3.1** and classified as:

| Severity | CVSS Score | Example |
|----------|------------|---------|
| **Critical** | 9.0 – 10.0 | Auth bypass, full data exposure |
| **High** | 7.0 – 8.9 | SQL injection, broken access control |
| **Medium** | 4.0 – 6.9 | Missing rate limiting, CORS misconfiguration |
| **Low** | 0.1 – 3.9 | Missing security headers, verbose error messages |
| **Informational** | N/A | Best practice recommendations |

---

## Testing Timeline

| Phase | Activity | Estimated Time |
|-------|----------|----------------|
| Phase 1 | Environment setup | 2 hours |
| Phase 2 | Scope definition (this doc) | 1 hour |
| Phase 3 | Recon | 3 hours |
| Phase 4 | OWASP Top 10 testing | 8–10 hours |
| Phase 5 | Finding documentation | 3 hours |
| Phase 6 | Remediation | 3–4 hours |
| Phase 7 | Final report | 2 hours |

---

## Next Phase

→ **[Phase 3: Recon](phase3-recon.md)**  
Passive and active reconnaissance against the target — tech stack fingerprinting, endpoint discovery, HTTP header analysis, and JavaScript file review.

---

*Last updated: March 2026*