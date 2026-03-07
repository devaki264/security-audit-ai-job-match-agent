#!/usr/bin/env bash
# =============================================================================
# Security Audit Environment Setup
# AI Job Match Agent — Bug Bounty Style Assessment
# Author: Devakinandan Palla
# =============================================================================

set -e

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
RED="\033[0;31m"
RESET="\033[0m"

print_banner() {
  echo -e "${CYAN}"
  echo "╔══════════════════════════════════════════════════════════╗"
  echo "║        Security Audit Environment — Setup Script         ║"
  echo "║              AI Job Match Agent Assessment               ║"
  echo "╚══════════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
}

print_step() {
  echo -e "\n${BOLD}${GREEN}[+] $1${RESET}"
}

print_info() {
  echo -e "${YELLOW}[*] $1${RESET}"
}

print_error() {
  echo -e "${RED}[!] $1${RESET}"
}

check_os() {
  print_step "Detecting OS..."
  if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="mac"
    print_info "macOS detected — will use Homebrew"
    if ! command -v brew &>/dev/null; then
      print_error "Homebrew not found. Install it first: https://brew.sh"
      exit 1
    fi
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    print_info "Linux detected — will use apt"
  else
    print_error "Unsupported OS: $OSTYPE"
    exit 1
  fi
}

install_system_deps() {
  print_step "Installing system dependencies..."
  if [[ "$OS" == "mac" ]]; then
    brew update
    brew install nmap ffuf gobuster curl git jq wget
  else
    sudo apt-get update -qq
    sudo apt-get install -y nmap ffuf gobuster curl git jq wget python3 python3-pip golang-go
  fi
  print_info "System dependencies installed."
}

install_nuclei() {
  print_step "Installing Nuclei (template-based vulnerability scanner)..."
  if command -v nuclei &>/dev/null; then
    print_info "Nuclei already installed. Updating templates..."
    nuclei -update-templates
  else
    if [[ "$OS" == "mac" ]]; then
      brew install nuclei
    else
      # Install via Go
      go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
      export PATH=$PATH:$(go env GOPATH)/bin
      echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
    fi
    nuclei -update-templates
    print_info "Nuclei installed and templates updated."
  fi
}

install_python_tools() {
  print_step "Installing Python security tools..."
  pip3 install --upgrade pip --quiet
  pip3 install \
    requests \
    httpx \
    python-dotenv \
    beautifulsoup4 \
    lxml \
    shodan \
    dnspython \
    pyjwt \
    colorama \
    rich \
    --quiet
  print_info "Python packages installed."
}

install_whatweb() {
  print_step "Installing WhatWeb (tech stack fingerprinting)..."
  if command -v whatweb &>/dev/null; then
    print_info "WhatWeb already installed."
  else
    if [[ "$OS" == "mac" ]]; then
      brew install whatweb
    else
      sudo apt-get install -y whatweb
    fi
  fi
}

install_nikto() {
  print_step "Installing Nikto (web server scanner)..."
  if command -v nikto &>/dev/null; then
    print_info "Nikto already installed."
  else
    if [[ "$OS" == "mac" ]]; then
      brew install nikto
    else
      sudo apt-get install -y nikto
    fi
  fi
}

setup_project_dirs() {
  print_step "Creating project directory structure..."
  mkdir -p security-audit-ai-job-match-agent/{docs/findings,evidence/screenshots,evidence/burp-exports,tools,reports}

  cat > security-audit-ai-job-match-agent/.env.example <<EOF
# Target configuration — copy to .env and fill in
TARGET_DOMAIN=your-domain.com
TARGET_BASE_URL=https://your-domain.com
CLOUDFLARE_WORKER_URL=https://your-worker.workers.dev
# Never commit .env to git
EOF

  cat > security-audit-ai-job-match-agent/.gitignore <<EOF
.env
evidence/screenshots/*.png
evidence/burp-exports/*.xml
*.log
__pycache__/
.DS_Store
node_modules/
EOF

  print_info "Project structure created in ./security-audit-ai-job-match-agent/"
}

install_burpsuite_reminder() {
  print_step "Burp Suite Community Edition (manual install required)"
  echo ""
  echo -e "${YELLOW}  Burp Suite cannot be installed via script. Do this manually:${RESET}"
  echo ""
  echo "  1. Go to: https://portswigger.net/burp/communitydownload"
  echo "  2. Download the installer for your OS"
  echo "  3. Install the CA certificate in your browser:"
  echo "     → Start Burp → Proxy → Options → Import/Export CA Certificate"
  echo "     → Import into Firefox/Chrome under Trusted Authorities"
  echo ""
  echo -e "${YELLOW}  Browser extension recommended:${RESET}"
  echo "  → FoxyProxy (Firefox/Chrome) — lets you toggle Burp proxy on/off quickly"
  echo ""
}

verify_installs() {
  print_step "Verifying installations..."
  tools=("nmap" "nuclei" "ffuf" "nikto" "whatweb" "curl" "jq")
  for tool in "${tools[@]}"; do
    if command -v "$tool" &>/dev/null; then
      echo -e "  ${GREEN}✓${RESET} $tool"
    else
      echo -e "  ${RED}✗${RESET} $tool — not found, check manually"
    fi
  done
}

print_next_steps() {
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗"
  echo    "║                     Setup Complete!                      ║"
  echo    "╚══════════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
  echo -e "${BOLD}Next steps:${RESET}"
  echo "  1. Install Burp Suite Community manually (link printed above)"
  echo "  2. cd security-audit-ai-job-match-agent"
  echo "  3. cp .env.example .env && fill in your target URLs"
  echo "  4. Open Phase 2: scope.md and define your scope"
  echo ""
  echo -e "${YELLOW}  Run your first scan:${RESET}"
  echo "    nmap -sV -sC your-domain.com"
  echo "    whatweb https://your-domain.com"
  echo "    nuclei -u https://your-domain.com -t exposures/"
  echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
print_banner
check_os
install_system_deps
install_nuclei
install_python_tools
install_whatweb
install_nikto
setup_project_dirs
install_burpsuite_reminder
verify_installs
print_next_steps
