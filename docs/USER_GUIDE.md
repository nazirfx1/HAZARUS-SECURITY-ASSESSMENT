# HAZARUS Documentation

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Configuration](#configuration)
4. [Modules](#modules)
5. [CLI Reference](#cli-reference)
6. [API Reference](#api-reference)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites

- Parrot Security OS or Debian-based Linux
- Python 3.11 or higher
- sudo access

### Quick Install

```bash
# Clone repository
git clone https://github.com/hazarus/hazarus.git
cd hazarus

# Run installation script
sudo bash install.sh
```

### Manual Install

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install HAZARUS
pip install -e .

# Install external tools (optional)
sudo apt update
sudo apt install nmap anonsurf nikto
```

## Quick Start

```bash
# Initialize project
hazarus init

# Edit scope configuration
nano config/scope.yaml

# Validate scope
hazarus scope validate

# Check privacy
hazarus privacy check

# Run reconnaissance
hazarus recon example.com

# Generate report
hazarus report <assessment-id> --format html
```

## Configuration

### Scope Configuration

Located at `config/scope.yaml`:

```yaml
allowed_targets:
  - "192.168.1.100"
  - "example.com"
allowed_domains:
  - "example.com"
allowed_cidrs:
  - "192.168.1.0/24"
excluded_targets:
  - "192.168.1.1"
allowed_ports:
  - 80, 443, 22
assessment_window:
  start: "2024-01-01T00:00:00"
  end: "2024-12-31T23:59:59"
intensity: normal
rate_limit: 100
request_limit: 10000
```

### HAZARUS Configuration

Located at `config/hazarus.yaml`:

```yaml
assessment:
  intensity: normal
  privacy_mode: strict
  max_threads: 10
  timeout: 300

logging:
  level: INFO
  file: logs/hazarus.log

privacy:
  require_anonsurf: true
  block_on_dns_leak: true
  block_on_ipv6_exposure: true
```

## Modules

### Core Modules

- **engine.py** - Main orchestration engine
- **orchestrator.py** - Phase coordination
- **scheduler.py** - Task scheduling
- **event_bus.py** - Event system
- **task_manager.py** - Concurrent task execution
- **state_manager.py** - Persistent state management

### Security Modules

- **scope.py** - Target authorization and scope enforcement
- **authorization.py** - Operator and client authorization
- **safety_gate.py** - Safety policy enforcement
- **audit_logger.py** - Comprehensive audit logging
- **policy_engine.py** - Security policy evaluation

### Anonymity Modules

- **anonsurf.py** - Anonsurf integration
- **tor_check.py** - Tor connectivity validation
- **dns_leak.py** - DNS leak detection
- **ipv6_check.py** - IPv6 exposure detection
- **proxy_validation.py** - Proxy configuration validation
- **privacy_report.py** - Privacy readiness reports

### Reconnaissance Modules

- **dns.py** - DNS enumeration
- **whois.py** - WHOIS/RDAP queries
- **subdomains.py** - Subdomain discovery
- **crtsh.py** - Certificate Transparency logs
- **passive_recon.py** - Passive information gathering
- **asset_inventory.py** - Asset discovery and inventory

### Scanning Modules

- **nmap.py** - Nmap integration
- **service_detection.py** - Service detection
- **tls_analysis.py** - TLS configuration analysis
- **http_scanner.py** - HTTP security scanning
- **web_crawler.py** - Web application crawling
- **api_discovery.py** - API endpoint discovery

### Vulnerability Modules

- **nuclei.py** - Nuclei vulnerability scanning
- **owasp_zap.py** - OWASP ZAP integration
- **nikto.py** - Nikto web server scanning
- **cvss.py** - CVSS score calculation
- **cve_matcher.py** - CVE matching and correlation
- **exploitdb.py** - Exploit-DB integration
- **github_advisories.py** - GitHub Security Advisories

### Exploitation Modules

- **exploit_engine.py** - Exploit execution engine
- **exploit_registry.py** - Exploit metadata registry
- **exploit_matcher.py** - Exploit matching
- **metasploit_rpc.py** - Metasploit RPC client
- **validation.py** - Exploit validation
- **lab_executor.py** - Isolated lab execution
- **cleanup_manager.py** - Cleanup and rollback

### Post-Assessment Modules

- **privilege_audit.py** - Privilege escalation audit
- **credential_exposure.py** - Credential exposure detection
- **lateral_movement_audit.py** - Lateral movement analysis
- **persistence_audit.py** - Persistence mechanism audit
- **exfiltration_simulation.py** - Data exfiltration simulation
- **segmentation_audit.py** - Network segmentation audit

### Code Analysis Modules

- **semgrep.py** - Semgrep static analysis
- **gitleaks.py** - Gitleaks secret detection
- **trivy.py** - Trivy vulnerability scanning
- **dependency_audit.py** - Dependency vulnerability analysis
- **secret_analysis.py** - Secret pattern analysis

### Reporting Modules

- **report_engine.py** - Report generation engine
- **executive_summary.py** - Executive summary generation
- **evidence_manager.py** - Evidence collection and management
- **html_report.py** - HTML report generation
- **pdf_report.py** - PDF report generation
- **json_report.py** - JSON report generation

## CLI Reference

### Initialization
- `hazarus init` - Initialize new assessment project

### Scope & Authorization
- `hazarus scope validate` - Validate scope configuration

### Privacy
- `hazarus privacy check` - Check anonymity configuration

### Assessment
- `hazarus recon <targets>` - Run reconnaissance
- `hazarus scan <targets>` - Run network scan
- `hazarus web <targets>` - Run web assessment
- `hazarus api <targets>` - Run API security assessment

### Research
- `hazarus research [--cve-id] [--service] [--version]` - Research vulnerabilities

### Exploitation
- `hazarus exploit list` - List available exploits
- `hazarus exploit inspect <id>` - Inspect exploit details
- `hazarus exploit check <id> <target>` - Check exploit compatibility
- `hazarus exploit lab <id> <target>` - Execute in lab environment

### Post-Assessment
- `hazarus post audit <target>` - Post-exploitation audit
- `hazarus lateral audit <target>` - Lateral movement audit
- `hazarus persistence audit <target>` - Persistence audit
- `hazarus exfil simulate <target>` - Exfiltration simulation

### Code Analysis
- `hazarus code analyze <path>` - Analyze source code

### Reporting
- `hazarus report <id> [--format]` - Generate assessment report

### Dashboard
- `hazarus dashboard [--host] [--port]` - Start web dashboard

### Maintenance
- `hazarus update` - Update HAZARUS

## API Reference

### Dashboard API

**Base URL:** `http://127.0.0.1:8000`

#### Endpoints

- `GET /` - API status
- `GET /assessments` - List assessments
- `GET /assessments/{id}` - Get assessment details
- `POST /assessments` - Create assessment
- `GET /assessments/{id}/findings` - Get findings
- `GET /vulnerabilities` - List vulnerabilities
- `GET /scope` - Get scope configuration
- `POST /scope` - Update scope
- `GET /dashboard/stats` - Dashboard statistics

## Security Considerations

### Important Notes

1. **Authorization Required** - All assessments require explicit target authorization
2. **Scope Enforcement** - Framework strictly enforces scope boundaries
3. **Privacy First** - Anonsurf and Tor are strongly recommended
4. **Lab Only** - Exploitation should only be performed in isolated lab environments
5. **Audit Logging** - All operations are logged for accountability
6. **No Automatic Exploitation** - Exploits require explicit operator approval

### Privacy Gate

- Anonsurf verification before assessments
- DNS leak detection
- IPv6 exposure detection
- Tor connectivity validation
- Tool proxy compatibility checks

### Safety Gates

- Scope validation before each operation
- Authorization verification
- Rate limiting
- Assessment window enforcement
- Emergency stop capability

## Troubleshooting

### Common Issues

**Issue:** "Scope file not found"
**Solution:** Run `hazarus init` to create configuration files

**Issue:** "Privacy verification failed"
**Solution:** Start Anonsurf with `sudo anonsurf start`

**Issue:** "Nmap not found"
**Solution:** Install with `sudo apt install nmap`

**Issue:** "Module import error"
**Solution:** Ensure you're in a virtual environment and dependencies are installed

### Debug Mode

Enable debug logging by setting `log_level: DEBUG` in `config/hazarus.yaml`

### Logs

Logs are stored in `~/.hazarus/logs/`

Audit logs are stored in `~/.hazarus/audit_logs/`
