# F005 — Missing Rate Limiting on API Endpoints

**Date Discovered:** March 2026  
**Discovered By:** Devakinandan Palla  
**Phase:** 4 — OWASP Top 10 Testing  
**Tool Used:** Burp Suite Community Edition — Repeater  

---

## Summary

The `/api/monitoring` endpoint and other authenticated API routes do not implement rate limiting. Repeated requests are served without throttling, returning HTTP 200 until the session naturally expires. No HTTP 429 (Too Many Requests) response was observed at any point during testing.

---

## Severity

| Property | Value |
|----------|-------|
| **Severity** | Medium |
| **CVSS v3.1 Score** | 5.3 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L |
| **OWASP Category** | A04:2021 — Insecure Design |
| **CWE** | CWE-770: Allocation of Resources Without Limits |

---

## Affected Endpoints

```
GET /api/monitoring
GET /api/jobs (if exists)
POST /api/auth/* 
```

---

## Steps to Reproduce

1. Log in to the application via Google OAuth
2. Open Burp Suite → Proxy → HTTP History
3. Locate a `GET /api/monitoring` request
4. Right-click → Send to Repeater
5. Click **Send** repeatedly (50+ times in rapid succession)
6. Observe: every request returns `HTTP/2 200 OK` with no throttling
7. No `429 Too Many Requests` response was observed at any point
8. Session eventually expired naturally (401) — not due to rate limiting

---

## Evidence

**Burp Suite Repeater — request sent 50+ times:**
```
GET /api/monitoring HTTP/2
Host: ai-job-match-agent-686566480080.us-central1.run.app
Cookie: sb-gzfvajgeujslvnbnadgs-auth-token.0=[token]
```

**Response — consistent across all attempts:**
```json
HTTP/2 200 OK
{
  "success": true,
  "monitoring_active": false
}
```

**No rate limit headers observed:**
- `X-RateLimit-Limit` — absent
- `X-RateLimit-Remaining` — absent
- `Retry-After` — absent

> Screenshot: evidence/screenshots/F005-repeater-200-responses.png

---

## Impact

Without rate limiting an attacker can:

- **Enumerate data** by sending thousands of requests to extract information
- **Abuse email notifications** — if the monitoring toggle endpoint has no rate limit, an attacker could trigger mass email sending by rapidly toggling monitoring on/off
- **Resource exhaustion** — sustained high-volume requests could increase GCP Cloud Run costs and degrade performance for legitimate users
- **Credential stuffing** — auth endpoints without rate limiting are vulnerable to automated login attempts

The most significant risk for this specific application is the email alert system — an attacker with a valid session could potentially trigger thousands of job alert emails by rapidly calling the monitoring toggle endpoint.

---

## Remediation

Implement rate limiting at the Next.js middleware level using a library like `@upstash/ratelimit` with Redis (already in the stack):

```typescript
// lib/ratelimit.ts
import { Ratelimit } from "@upstash/ratelimit"
import { Redis } from "@upstash/redis"

export const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, "10 s"), // 10 requests per 10 seconds
})

// middleware.ts
import { ratelimit } from "@/lib/ratelimit"

export async function middleware(request: NextRequest) {
  const ip = request.ip ?? "127.0.0.1"
  const { success } = await ratelimit.limit(ip)

  if (!success) {
    return new NextResponse("Too Many Requests", { status: 429 })
  }
}
```

**Recommended limits by endpoint type:**

| Endpoint | Limit |
|----------|-------|
| Auth endpoints | 5 requests / minute |
| API monitoring toggle | 10 requests / minute |
| General API routes | 60 requests / minute |

---

## Remediation Status

- [x] Identified
- [ ] Fix implemented
- [ ] Fix verified

---

## References

- [OWASP Rate Limiting](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)
- [Upstash Rate Limiting for Next.js](https://upstash.com/docs/oss/sdks/ts/ratelimit/overview)
- [CWE-770](https://cwe.mitre.org/data/definitions/770.html)

---

*Finding documented as part of self-directed security assessment of AI Job Match Agent*