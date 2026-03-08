# -*- coding: utf-8 -*-
"""
Phase 3: Reconnaissance Script
AI Job Match Agent Security Assessment
Author: Devakinandan Palla

Usage: python tools/recon.py
Output: reports/recon-output.txt
"""

import requests
import socket
import ssl
import datetime
import os
import sys

# Force UTF-8 output on Windows
sys.stdout.reconfigure(encoding='utf-8')

TARGET = "https://ai-job-match-agent-686566480080.us-central1.run.app"
OUTPUT_FILE = "reports/recon-output.txt"

def header(title):
    line = "=" * 60
    return f"\n{line}\n  {title}\n{line}\n"

def save(f, text):
    print(text)
    f.write(text + "\n")

def check_headers(f):
    save(f, header("1. HTTP RESPONSE HEADERS"))
    try:
        r = requests.get(TARGET, timeout=10)
        save(f, f"Status Code: {r.status_code}")
        save(f, f"Final URL:   {r.url}\n")

        security_headers = {
            "Strict-Transport-Security": "HSTS - forces HTTPS",
            "Content-Security-Policy": "CSP - prevents XSS",
            "X-Frame-Options": "Prevents clickjacking",
            "X-Content-Type-Options": "Prevents MIME sniffing",
            "Referrer-Policy": "Controls referrer info leakage",
            "Permissions-Policy": "Controls browser features",
            "X-XSS-Protection": "Legacy XSS filter",
            "Cache-Control": "Controls caching behavior",
        }

        save(f, "--- Security Header Analysis ---")
        missing = []
        present = []
        for header_name, description in security_headers.items():
            value = r.headers.get(header_name)
            if value:
                save(f, f"  [PRESENT]  {header_name}: {value}")
                save(f, f"             {description}")
                present.append(header_name)
            else:
                save(f, f"  [MISSING]  {header_name}")
                save(f, f"             {description}")
                missing.append(header_name)

        save(f, f"\nSummary: {len(present)} present, {len(missing)} missing")
        save(f, f"Missing: {', '.join(missing)}")

        save(f, "\n--- All Response Headers ---")
        for k, v in r.headers.items():
            save(f, f"  {k}: {v}")

    except Exception as e:
        save(f, f"ERROR: {e}")

def check_ssl(f):
    save(f, header("2. SSL/TLS CERTIFICATE"))
    try:
        from urllib.parse import urlparse
        hostname = urlparse(TARGET).hostname
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            cert = s.getpeercert()

        save(f, f"  Subject:    {dict(x[0] for x in cert['subject'])}")
        save(f, f"  Issuer:     {dict(x[0] for x in cert['issuer'])}")
        save(f, f"  Valid From: {cert['notBefore']}")
        save(f, f"  Valid To:   {cert['notAfter']}")

        expiry = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.datetime.utcnow()).days
        if days_left < 30:
            save(f, f"  [WARNING] Certificate expires in {days_left} days!")
        else:
            save(f, f"  [OK] Certificate valid for {days_left} more days")

    except Exception as e:
        save(f, f"ERROR: {e}")

def check_endpoints(f):
    save(f, header("3. COMMON ENDPOINT DISCOVERY"))
    endpoints = [
        "/", "/login", "/dashboard", "/api", "/api/health",
        "/api/jobs", "/api/user", "/api/auth", "/auth/callback",
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/.env", "/.env.local", "/config", "/admin", "/api/admin",
        "/_next/static", "/favicon.ico", "/api/docs", "/swagger", "/openapi.json",
    ]

    for endpoint in endpoints:
        url = TARGET + endpoint
        try:
            r = requests.get(url, timeout=8, allow_redirects=False)
            flag = ""
            if r.status_code == 200:
                flag = "  <- ACCESSIBLE"
            elif r.status_code in [301, 302, 307]:
                flag = f"  <- REDIRECT -> {r.headers.get('Location', '?')}"
            elif r.status_code == 403:
                flag = "  <- FORBIDDEN"
            elif r.status_code == 401:
                flag = "  <- UNAUTHORIZED"
            save(f, f"  {r.status_code}  {url}{flag}")
        except Exception as e:
            save(f, f"  ERR  {url} - {e}")

def check_info_disclosure(f):
    save(f, header("4. INFORMATION DISCLOSURE"))
    sensitive_paths = [
        "/.env", "/.env.local", "/.env.production",
        "/config.json", "/package.json", "/.git/config",
        "/.git/HEAD", "/server.js", "/next.config.js", "/api/config",
    ]
    for path in sensitive_paths:
        url = TARGET + path
        try:
            r = requests.get(url, timeout=8)
            if r.status_code == 200 and len(r.text) > 0:
                save(f, f"  [!!!] EXPOSED: {url}")
                save(f, f"        Preview: {r.text[:200]}")
            else:
                save(f, f"  [OK]  {url} -> {r.status_code}")
        except Exception as e:
            save(f, f"  ERR  {url} - {e}")

def check_cookies(f):
    save(f, header("5. COOKIE SECURITY ANALYSIS"))
    try:
        r = requests.get(TARGET, timeout=10)
        if not r.cookies:
            save(f, "  No cookies set on homepage (check after login via browser)")
        for cookie in r.cookies:
            val = cookie.value[:40] + "..." if len(cookie.value) > 40 else cookie.value
            save(f, f"\n  Cookie: {cookie.name}")
            save(f, f"    Value:  {val}")
            save(f, f"    Domain: {cookie.domain}")
            save(f, f"    Secure: {'[OK]' if cookie.secure else '[MISSING]'}")
    except Exception as e:
        save(f, f"ERROR: {e}")

def check_cors(f):
    save(f, header("6. CORS CONFIGURATION"))
    for origin in ["https://evil.com", "https://attacker.com", "null", TARGET]:
        try:
            r = requests.get(TARGET, headers={"Origin": origin}, timeout=8)
            acao = r.headers.get("Access-Control-Allow-Origin", "Not set")
            acac = r.headers.get("Access-Control-Allow-Credentials", "Not set")
            save(f, f"  Origin: {origin}")
            save(f, f"    ACAO: {acao}  |  ACAC: {acac}")
            if acao == origin and origin == "https://evil.com":
                save(f, f"    [!!!] VULNERABILITY: Reflects arbitrary origin!")
        except Exception as e:
            save(f, f"  ERR - {e}")

def check_missing_files(f):
    save(f, header("7. MISSING SECURITY FILES"))
    files = {
        "/robots.txt": "Crawler access control",
        "/.well-known/security.txt": "Security contact (RFC 9116)",
        "/sitemap.xml": "Site structure",
    }
    for path, description in files.items():
        url = TARGET + path
        try:
            r = requests.get(url, timeout=8)
            status = "[OK]" if r.status_code == 200 else f"[MISSING] - {description}"
            save(f, f"  {r.status_code}  {path}  {status}")
        except Exception as e:
            save(f, f"  ERR  {path} - {e}")

def main():
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        save(f, "SECURITY RECON REPORT - AI JOB MATCH AGENT")
        save(f, f"Generated: {timestamp}")
        save(f, f"Target:    {TARGET}")
        save(f, f"Author:    Devakinandan Palla")

        check_headers(f)
        check_ssl(f)
        check_endpoints(f)
        check_info_disclosure(f)
        check_cookies(f)
        check_cors(f)
        check_missing_files(f)

        save(f, header("RECON COMPLETE"))
        save(f, f"Output saved to: {OUTPUT_FILE}")
        save(f, "Next: Phase 4 - OWASP Top 10 testing")

    print(f"\nReport saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()