# F001 — Flash of Unauthenticated Content (FOUC) on /dashboard

**Date Discovered:** March 2026  
**Discovered By:** Devakinandan Palla  
**Phase:** 3 — Reconnaissance  

---

## Summary

The `/dashboard` route briefly renders its HTML content to unauthenticated users before the server-side redirect to `/auth/login` completes. This exposes the dashboard UI layout, component structure, and potentially partial data to unauthenticated users for a brief window (~200–500ms).

---

## Severity

| Property | Value |
|----------|-------|
| **Severity** | Medium |
| **CVSS v3.1 Score** | 4.3 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N |
| **OWASP Category** | A01:2021 — Broken Access Control |
| **CWE** | CWE-287: Improper Authentication |

---

## Affected Asset

```
https://ai-job-match-agent-686566480080.us-central1.run.app/dashboard
```

---

## Steps to Reproduce

1. Open an incognito browser window (no active session)
2. Navigate directly to:
   ```
   https://ai-job-match-agent-686566480080.us-central1.run.app/dashboard
   ```
3. Observe: dashboard UI briefly renders before redirecting to `/auth/login`
4. To confirm: open DevTools → Network tab before navigating — observe the initial 200 response for `/dashboard` before the 307 redirect fires

---

## Evidence

**Observed behavior:**
- Initial HTTP response for `/dashboard`: `200 OK`
- Dashboard HTML and React components render in browser
- Auth check runs client-side in JavaScript
- Redirect to `/auth/login` fires ~200–500ms after initial render

**Network sequence:**
```
GET /dashboard        → 200 OK  (dashboard HTML served)
GET /auth/login       → 307 redirect (auth check failed, user redirected)
```

> Screenshot: see evidence/screenshots/F001-dashboard-fouc.png

---

## Impact

- **What an attacker sees:** Dashboard UI layout, component names, and any data that loads before the auth check resolves
- **What they cannot access:** Protected API routes still require valid session tokens — server-side data is not exposed
- **Risk:** Low-to-medium. In the current implementation, no sensitive data appears to load before redirect. However, if any client-side data fetching begins before the auth check resolves, user data could be momentarily visible.

---

## Root Cause

Authentication is enforced client-side via a JavaScript `useEffect` hook or equivalent, which runs **after** the initial render cycle. This is a common pattern in Next.js apps that rely on client-side auth guards:

```javascript
// Vulnerable pattern — auth check runs after render
useEffect(() => {
  if (!session) router.push('/auth/login')
}, [session])
```

The page renders first, then redirects — rather than blocking render until auth is confirmed.

---

## Remediation

Move authentication enforcement to Next.js **middleware**, which runs server-side before any page is rendered:

```typescript
// middleware.ts (place in project root)
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { getToken } from 'next-auth/jwt'

export async function middleware(request: NextRequest) {
  const token = await getToken({ req: request })
  
  if (!token) {
    return NextResponse.redirect(new URL('/auth/login', request.url))
  }
  
  return NextResponse.next()
}

export const config = {
  matcher: ['/dashboard/:path*', '/api/protected/:path*']
}
```

This ensures the server validates the session **before** serving the dashboard HTML, eliminating the flash entirely.

---

## Remediation Status

- [x] Identified
- [ ] Reported to development team
- [ ] Fix implemented
- [ ] Fix verified

---

## References

- [Next.js Middleware Documentation](https://nextjs.org/docs/advanced-features/middleware)
- [OWASP A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

---

*Finding documented as part of self-directed security assessment of AI Job Match Agent*