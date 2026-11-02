# HAZARUS Module Dependency Map

**Created:** 2025-01-01
**Framework Version:** 2.0.0

---

## Dependency Graph

```
HAZARUS CLI (hazarus/cli.py)
├── Core Engine
│   ├── core/engine.py
│   ├── core/orchestrator.py
│   ├── core/scheduler.py
│   ├── core/event_bus.py
│   ├── core/task_manager.py
│   └── core/state_manager.py
├── Security Layer
│   ├── security/scope.py
│   ├── security/authorization.py
│   ├── security/safety_gate.py
│   ├── security/audit_logger.py
│   └── security/policy_engine.py
├── Anonymity Layer
│   ├── anonymity/anonsurf.py
│   ├── anonymity/tor_check.py
│   ├── anonymity/dns_leak.py
│   ├── anonymity/ipv6_check.py
│   ├── anonymity/proxy_validation.py
│   └── anonymity/privacy_report.py
├── Reconnaissance Layer
│   ├── reconnaissance/dns.py
│   ├── reconnaissance/whois.py
│   ├── reconnaissance/subdomains.py
│   ├── reconnaissance/crtsh.py
│   ├── reconnaissance/passive_recon.py
│   └── reconnaissance/asset_inventory.py
├── Scanning Layer
│   ├── scanning/nmap.py
│   ├── scanning/service_detection.py
│   ├── scanning/tls_analysis.py
│   ├── scanning/http_scanner.py
│   ├── scanning/web_crawler.py
│   └── ├── scanning/api_discovery.py
├── Vulnerability Layer
│   ├── vulnerability/nuclei.py
│   ├── vulnerability/owasp_zap.py
│   ├── vulnerability/nikto.py
│   ├── vulnerability/cvss.py
│   ├── vulnerability/cve_matcher.py
│   ├── vulnerability/exploitdb.py
│   └── vulnerability/github_advisories.py
├── Exploitation Layer
│   ├── exploitation/exploit_engine.py
│   ├── exploitation/exploit_registry.py
│   ├── exploitation/exploit_matcher.py
│   ├── exploitation/metasploit_rpc.py
│   ├── exploitation/validation.py
│   ├── exploitation/lab_executor.py
│   └── exploitation/cleanup_manager.py
├── Post-Assessment Layer
│   ├── post_assessment/privilege_audit.py
│   ├── post_assessment/credential_exposure.py
│   ├── post_assessment/lateral_movement_audit.py
│   ├── post_assessment/persistence_audit.py
│   ├── post_assessment/exfiltration_simulation.py
│   └── post_assessment/segmentation_audit.py
├── Code Analysis Layer
│   ├── code_analysis/semgrep.py
│   ├── code_analysis/gitleaks.py
│   ├── code_analysis/trivy.py
│   ├── code_analysis/dependency_audit.py
│   └── code_analysis/secret_analysis.py
├── Reporting Layer
│   ├── reporting/report_engine.py
│   ├── reporting/executive_summary.py
│   ├── reporting/evidence_manager.py
│   ├── reporting/html_report.py
│   ├── reporting/pdf_report.py
│   └── reporting/json_report.py
└── Dashboard Layer
    ├── dashboard/backend/main.py
    └── dashboard/frontend/
```

---

## Layer Dependencies

### Core Layer (No External Dependencies)
- Pure Python asyncio-based architecture
- Dataclasses for state management
- No external tool dependencies

### Security Layer (No External Dependencies)
- Pure Python validation logic
- YAML configuration parsing
- No external tool dependencies

### Anonymity Layer (System Dependencies)
- **Required:** Linux system tools (anonsurf, systemctl, test)
- **Optional:** Tor daemon
- **Platform:** Linux-only (Parrot OS primary)

### Reconnaissance Layer (External Dependencies)
- **dnspython** - DNS resolution
- **python-whois** - WHOIS queries
- **httpx** - HTTP requests
- **Optional:** External DNS APIs

### Scanning Layer (External Tool Dependencies)
- **nmap** - Network scanning (primary)
- **Optional:** sslscan, testssl.sh
- **Platform:** Cross-platform (nmap available on Windows/Linux/macOS)

### Vulnerability Layer (External Tool Dependencies)
- **nuclei** - Vulnerability scanning
- **nikto** - Web server scanning
- **Optional:** OWASP ZAP
- **httpx** - HTTP requests
- **aiohttp** - Async HTTP

### Exploitation Layer (External Tool Dependencies)
- **Metasploit Framework** - Exploit execution
- **msfrpcd** - RPC daemon
- **httpx** - RPC communication
- **Platform:** Linux-only (Metasploit primary platform)

### Post-Assessment Layer (System Dependencies)
- **Required:** Linux system tools (systemctl, find, getcap, sudo, ls, cat, grep, arp, smbclient, ip, iptables)
- **Platform:** Linux-only (system-specific commands)

### Code Analysis Layer (External Tool Dependencies)
- **semgrep** - Static analysis
- **gitleaks** - Secret detection
- **trivy** - Vulnerability scanning
- **Platform:** Cross-platform

### Reporting Layer (Python Dependencies)
- **reportlab** - PDF generation
- **weasyprint** - HTML to PDF
- **jinja2** - Template rendering
- **Platform:** Cross-platform

### Dashboard Layer (Full Stack)
- **Backend:** FastAPI, uvicorn, SQLAlchemy
- **Frontend:** React, TypeScript, Vite, Tailwind CSS
- **Platform:** Cross-platform

---

## Python Package Dependencies

### Core Dependencies
- typer - CLI framework
- pydantic - Data validation
- pydantic-settings - Configuration management
- rich - Terminal UI

### Async Runtime
- asyncio - Built-in
- aiohttp - Async HTTP client
- httpx - Async HTTP client

### Network & DNS
- dnspython - DNS resolution
- python-whois - WHOIS queries
- requests - HTTP client
- beautifulsoup4 - HTML parsing
- lxml - XML/HTML parsing

### Security
- cryptography - Cryptographic operations
- validators - Input validation

### Reporting
- jinja2 - Template engine
- reportlab - PDF generation
- weasyprint - HTML to PDF
- markupsafe - Safe string handling

### Configuration
- pyyaml - YAML parsing
- toml - TOML parsing
- python-dotenv - Environment variables

### Web
- fastapi - Web framework
- uvicorn - ASGI server
- sqlalchemy - ORM

### System
- psutil - System monitoring
- netaddr - Network address manipulation
- ipaddress - IP address manipulation (built-in)

### Testing
- pytest - Test framework
- pytest-asyncio - Async test support
- pytest-cov - Coverage reporting

---

## External Tool Dependencies Matrix

| Tool | Required | Platform | Module | Status |
|------|----------|---------|--------|--------|
| nmap | Optional | Cross | scanning/nmap.py | ✅ Implemented |
| anonsurf | Optional | Linux | anonymity/anonsurf.py | ✅ Implemented |
| nikto | Optional | Cross | vulnerability/nikto.py | ✅ Implemented |
| nuclei | Optional | Cross | vulnerability/nuclei.py | ✅ Implemented |
| semgrep | Optional | Cross | code_analysis/semgrep.py | ✅ Implemented |
| gitleaks | Optional | Cross | code_analysis/gitleaks.py | ✅ Implemented |
| trivy | Optional | Cross | code_analysis/trivy.py | ✅ Implemented |
| Metasploit | Optional | Linux | exploitation/metasploit_rpc.py | ✅ Implemented |
| OWASP ZAP | Optional | Cross | vulnerability/owasp_zap.py | ✅ Implemented |

---

## Module Inter-Module Dependencies

### Core → Security
- Core engine uses ScopeManager for validation
- Core engine uses AuditLogger for operation logging
- Core engine uses SafetyGate for operation approval

### Core → Anonymity
- Core engine uses AnonsurfManager for privacy verification
- Core engine uses PrivacyReport for status reporting

### Scanning → Vulnerability
- Scanning results feed into Vulnerability matching
- Service detection provides input for CVE matching

### Vulnerability → Exploitation
- CVE matching provides input for Exploit matching
- Vulnerability severity influences Exploit risk classification

### Exploitation → Post-Assessment
- Exploit execution triggers Post-Assessment audits
- Lab execution provides context for Privilege audits

### All Layers → Reporting
- All assessment phases produce findings for reports
- Evidence manager collects from all layers
- Report engine aggregates all layer data

---

## Circular Dependency Analysis

**Status:** ✅ No circular dependencies detected

The architecture follows a layered approach with unidirectional dependencies:
- CLI → Core
- Core → Security, Anonymity
- Core → Assessment Layers (Recon, Scan, Vuln, Exploit, Post-Assessment)
- Assessment Layers → Reporting
- Core → Dashboard (optional)

---

## Installation Dependency Strategy

### Phase 1: Core Installation
- Install all Python dependencies from requirements.txt
- No external tools required for basic functionality

### Phase 2: Tool Installation (Optional)
- Install nmap for network scanning
- Install anonsurf for anonymity (Linux only)
- Install nikto for web scanning

### Phase 3: Advanced Tools (Optional)
- Install nuclei for vulnerability scanning
- Install semgrep for code analysis
- Install gitleaks for secret detection
- Install trivy for dependency scanning

### Phase 4: Exploitation Tools (Linux Only)
- Install Metasploit Framework
- Configure msfrpcd

### Phase 5: Dashboard (Optional)
- Install Node.js for frontend
- Install frontend dependencies

---

## Dependency Version Pinning

Current status: Version ranges specified (>=)

Recommendation: Pin exact versions for production releases to ensure reproducibility.

---

## Missing Dependencies

**None identified** - All Python dependencies are listed in requirements.txt.

**External tools** are optional and gracefully handled with availability checks.
