"""
Phase 3: Reconnaissance Script
AI Job Match Agent Security Assessment
Author: Devakinandan Palla

Runs passive + active recon against the target and saves results to /reports/recon-output.txt
Usage: python tools/recon.py
"""

import requests
import json
import socket
import ssl
import datetime
import os
import sys
from urllib.parse import urlparse

TARGET = "https://ai-job-match-agent-686566480080.us-central1.run.app"
OUTPUT_FILE = "reports/recon-output.txt"

# ── Helpers ────────────────────────────────────────────────────────────────────

def header(title):
    line = "=" * 60
    return f"\n{line}\n  {title}\n{line}\n"

def save(f, text):
    print(text)
    f.write(text + "\n")

# ── 1. HTTP Response Headers ───────────────────────────────────────────────────

def check_headers(f):
    save(f, header("1. HTTP RESPONSE HEADERS"))
    try:
        r = requests.get(TARGET, timeout=10)
        save(f, f"Status Code: {r.status_code}")
        save(f, f"Final URL:   {r.url}\n")

        security_headers = {
            "Strict-Transport-Security": "HSTS — forces HTTPS",
            "Content-Security-Policy": "CSP — prevents XSS",
            "X-Frame-Options": "Prevents clickjacking",
            "X-Content-Type-Options": "Prevents MIME sniffing",
            "Referrer-Policy": "Controls referrer info leakage",
            "Permissions-Policy": "Controls browser features",
            "X-XSS-Protection": "Legacy XSS filter",
            "Cache-Control": "Controls caching behavior",
        }

        save(f, "--- Security Header Analysis ---")
        for header_name, description in security_headers.items():
            value = r.headers.get(header_name)
            if value:
                save(f, f"  [PRESENT]  {header_name}: {value}")
                save(f, f"             → {description}")
            else:
                save(f, f"  [MISSING]  {header_name}")
                save(f, f"             → {description}")

        save(f, "\n--- All Response Headers ---")
        for k, v in r.headers.items():
            save(f, f"  {k}: {v}")

    except Exception as e:
        save(f, f"ERROR: {e}")

# ── 2. SSL/TLS Certificate Info ────────────────────────────────────────────────

def check_ssl(f):
    save(f, header("2. SSL/TLS CERTIFICATE"))
    try:
        hostname = urlparse(TARGET).hostname
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            cert = s.getpeercert()

        save(f, f"  Subject:    {dict(x[0] for x in cert['subject'])}")
        save(f, f"  Issuer:     {dict(x[0] for x in cert['issuer'])}")
        save(f, f"  Valid From: {cert['notBefore']}")
        save(f, f"  Valid To:   {cert['notAfter']}")
        save(f, f"  SANs:       {cert.get('subjectAltName', 'N/A')}")

        # Check expiry
        expiry = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.datetime.utcnow()).days
        if days_left < 30:
            save(f, f"  [WARNING] Certificate expires in {days_left} days!")
        else:
            save(f, f"  [OK] Certificate valid for {days_left} more days")

    except Exception as e:
        save(f, f"ERROR: {e}")

# ── 3. Common Endpoint Discovery ──────────────────────────────────────────────

def check_endpoints(f):
    save(f, header("3. COMMON ENDPOINT DISCOVERY"))
    endpoints = [
        "/",
        "/login",
        "/dashboard",
        "/api",
        "/api/health",
        "/api/jobs",
        "/api/user",
        "/api/auth",
        "/auth/callback",
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/.env",
        "/.env.local",
        "/config",
        "/admin",
        "/api/admin",
        "/_next/static",
        "/favicon.ico",
        "/api/docs",
        "/swagger",
        "/openapi.json",
    ]

    for endpoint in endpoints:
        url = TARGET + endpoint
        try:
            r = requests.get(url, timeout=8, allow_redirects=False)
            flag = ""
            if r.status_code == 200:
                flag = "  ← [ACCESSIBLE]"
            elif r.status_code in [301, 302]:
                flag = f"  ← [REDIRECT] → {r.headers.get('Location', '?')}"
            elif r.status_code == 403:
                flag = "  ← [FORBIDDEN — exists but blocked]"
            elif r.status_code == 401:
                flag = "  ← [UNAUTHORIZED — auth required]"
            save(f, f"  {r.status_code}  {url}{flag}")
        except Exception as e:
            save(f, f"  ERR  {url} — {e}")

# ── 4. Information Disclosure Check ───────────────────────────────────────────

def check_info_disclosure(f):
    save(f, header("4. INFORMATION DISCLOSURE"))
    sensitive_paths = [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/config.json",
        "/package.json",
        "/.git/config",
        "/.git/HEAD",
        "/server.js",
        "/next.config.js",
        "/api/config",
    ]

    for path in sensitive_paths:
        url = TARGET + path
        try:
            r = requests.get(url, timeout=8)
            if r.status_code == 200 and len(r.text) > 0:
                save(f, f"  [!!!] EXPOSED: {url}")
                save(f, f"        Content preview: {r.text[:200]}")
            else:
                save(f, f"  [OK]  {url} → {r.status_code}")
        except Exception as e:
            save(f, f"  ERR  {url} — {e}")

# ── 5. Cookie Analysis ─────────────────────────────────────────────────────────

def check_cookies(f):
    save(f, header("5. COOKIE SECURITY ANALYSIS"))
    try:
        r = requests.get(TARGET, timeout=10)
        if not r.cookies:
            save(f, "  No cookies set on homepage.")
        for cookie in r.cookies:
            save(f, f"\n  Cookie: {cookie.name}")
            save(f, f"    Value:    {cookie.value[:40]}..." if len(cookie.value) > 40 else f"    Value:    {cookie.value}")
            save(f, f"    Domain:   {cookie.domain}")
            save(f, f"    Path:     {cookie.path}")
            save(f, f"    Secure:   {'[OK]' if cookie.secure else '[MISSING] ← should be True'}")
            save(f, f"    HttpOnly: {'[OK]' if cookie.has_nonstandard_attr('HttpOnly') else '[CHECK IN BROWSER]'}")
            save(f, f"    Expires:  {cookie.expires}")
    except Exception as e:
        save(f, f"ERROR: {e}")

# ── 6. CORS Configuration ──────────────────────────────────────────────────────

def check_cors(f):
    save(f, header("6. CORS CONFIGURATION"))
    test_origins = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        TARGET,
    ]
    for origin in test_origins:
        try:
            r = requests.get(
                TARGET,
                headers={"Origin": origin},
                timeout=8
            )
            acao = r.headers.get("Access-Control-Allow-Origin", "Not set")
            acac = r.headers.get("Access-Control-Allow-Credentials", "Not set")
            save(f, f"  Origin: {origin}")
            save(f, f"    Access-Control-Allow-Origin:      {acao}")
            save(f, f"    Access-Control-Allow-Credentials: {acac}")
            if acao == origin and origin == "https://evil.com":
                save(f, f"    [!!!] VULNERABILITY: Reflects arbitrary origin!")
            elif acao == "*" and acac == "true":
                save(f, f"    [!!!] VULNERABILITY: Wildcard + credentials!")
        except Exception as e:
            save(f, f"  ERR — {e}")

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(OUTPUT_FILE, "w") as f:
        save(f, f"SECURITY RECON REPORT — AI JOB MATCH AGENT")
        save(f, f"Generated: {timestamp}")
        save(f, f"Target:    {TARGET}")
        save(f, f"Author:    Devakinandan Palla")

        check_headers(f)
        check_ssl(f)
        check_endpoints(f)
        check_info_disclosure(f)
        check_cookies(f)
        check_cors(f)

        save(f, header("RECON COMPLETE"))
        save(f, f"Full output saved to: {OUTPUT_FILE}")
        save(f, "Next step: Review findings and move to Phase 4 — OWASP Top 10 testing")

    print(f"\n✓ Report saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()