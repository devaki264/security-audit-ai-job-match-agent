# Phase 1: Security Testing Environment Setup

**Project:** Bug Bounty Style Security Assessment — AI Job Match Agent  
**Author:** Devakinandan Palla  
**Phase:** 1 of 7  

---

## Overview

This document covers the complete setup of a professional security testing environment, mirroring tools used by bug bounty analysts at programs like HackerOne and Bugcrowd.

---

## Tools & Their Purpose

| Tool | Category | Why It's Used |
|------|----------|---------------|
| **Burp Suite Community** | Proxy / Interceptor | Capture, modify, and replay HTTP/S requests — the #1 tool for web security testing |
| **Nuclei** | Automated Scanner | Template-based scanner for known CVEs, misconfigurations, and exposures. Used by PayPal's own team (mentioned in the JD) |
| **nmap** | Network Recon | Port scanning, service detection, OS fingerprinting |
| **OWASP ZAP** | Automated Scanner | Complementary scanner to Nuclei, good for active scanning |
| **whatweb** | Fingerprinting | Identify tech stack visible externally (frameworks, servers, CMS) |
| **ffuf** | Fuzzing | Discover hidden endpoints, directories, and parameters |
| **gobuster** | Fuzzing | Directory/DNS brute-forcing |
| **nikto** | Web Scanner | Fast web server misconfiguration checks |
| **Python (httpx, requests, jwt)** | Scripting | Custom scripts for auth testing, token analysis, rate limit probing |

---

## Installation

### Option A: Automated (Recommended)

```bash
# Clone the repo first
git clone https://github.com/YOUR_USERNAME/security-audit-ai-job-match-agent
cd security-audit-ai-job-match-agent

# Make script executable and run
chmod +x tools/setup.sh
./tools/setup.sh
```

### Option B: Manual Installation

#### macOS (Homebrew)
```bash
brew install nmap ffuf gobuster whatweb nikto curl git jq wget
brew install nuclei
pip3 install requests httpx python-dotenv beautifulsoup4 pyjwt colorama rich
```

#### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y nmap ffuf gobuster whatweb nikto curl git jq wget python3 python3-pip golang-go
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
export PATH=$PATH:$(go env GOPATH)/bin
nuclei -update-templates
pip3 install requests httpx python-dotenv beautifulsoup4 pyjwt colorama rich
```

---

## Burp Suite Setup (Manual — Required)

Burp Suite cannot be installed via package manager. Follow these steps:

### Install
1. Download Community Edition: https://portswigger.net/burp/communitydownload
2. Run the installer for your OS
3. Launch Burp Suite → accept defaults → Start Burp

### Configure Browser Proxy
1. Install **FoxyProxy** extension (Firefox or Chrome)
2. Add a new proxy profile:
   - Host: `127.0.0.1`
   - Port: `8080`
3. Enable the proxy when testing, disable when done

### Install CA Certificate (Critical — Required for HTTPS)
1. With Burp running, go to `http://burpsuite` in your proxied browser
2. Click "CA Certificate" → download `cacert.der`
3. **Firefox:** Settings → Privacy & Security → Certificates → View Certificates → Import → select `cacert.der` → trust for websites
4. **Chrome:** Settings → Privacy → Security → Manage Certificates → Authorities → Import

> ⚠️ Without the CA cert, Burp cannot intercept HTTPS traffic and you'll see SSL errors.

---

## Project Directory Structure

After running `setup.sh`, you'll have:

```
security-audit-ai-job-match-agent/
├── README.md                    ← Executive summary (Phase 7)
├── docs/
│   ├── scope.md                 ← Phase 2: Scope definition
│   ├── methodology.md           ← Phase 3: Testing approach
│   └── findings/                ← Phase 5: One .md per vulnerability
│       ├── F001-template.md
│       └── ...
├── evidence/
│   ├── screenshots/             ← Burp/browser screenshots per finding
│   └── burp-exports/            ← Exported Burp request/response files
├── tools/
│   ├── setup.sh                 ← This setup script
│   ├── header_check.py          ← Phase 3: Security headers scanner
│   ├── rate_limit_test.py       ← Phase 4: Rate limiting probe
│   └── jwt_analyzer.py          ← Phase 4: JWT token analysis
├── reports/
│   └── final-report.md          ← Phase 7: Full compiled report
└── .env.example                 ← Target config template (never commit .env)
```

---

## Environment Configuration

```bash
cp .env.example .env
```

Edit `.env`:
```
TARGET_DOMAIN=your-app.com
TARGET_BASE_URL=https://your-app.com
CLOUDFLARE_WORKER_URL=https://your-worker.workers.dev
```

> `.env` is gitignored — never commit real URLs or tokens to a public repo.

---

## Verify Your Setup

Run this to confirm tools are working:

```bash
# Network recon
nmap --version
nmap -sV -sC $TARGET_DOMAIN

# Tech fingerprinting
whatweb https://$TARGET_DOMAIN

# First nuclei scan (safe, just exposures)
nuclei -u https://$TARGET_DOMAIN -t exposures/ -silent

# Fuzz for hidden endpoints
ffuf -w /usr/share/wordlists/dirb/common.txt -u https://$TARGET_DOMAIN/FUZZ
```

---

## Quick Reference: Burp Suite Workflow

```
Browser (FoxyProxy ON)
       ↓
Burp Proxy (127.0.0.1:8080) ← intercept, modify, replay
       ↓
Target App (your-app.com)
       ↓
Burp Repeater ← for testing individual requests
Burp Scanner  ← for automated passive scanning
Burp Intruder ← for fuzzing parameters (rate-limited in Community)
```

---

## Next Phase

→ **[Phase 2: Scope Definition](scope.md)**  
Define exactly what is in-scope vs. out-of-scope for this assessment, mirroring how real bug bounty programs structure their rules of engagement.

---

*Last updated: March 2026*
