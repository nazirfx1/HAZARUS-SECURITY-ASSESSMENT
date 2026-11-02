# HAZARUS Security Assessment Framework - Project Configuration

## Project Information

**Name:** HAZARUS Security Assessment Framework  
**Version:** 2.0.0  
**Platform:** Parrot Security OS (Linux)  
**Language:** Python 3.11+  

## Development Commands

### Installation
```bash
pip install -r requirements.txt
pip install -e .
```

### Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=hazarus

# Run specific test files
pytest tests/test_units.py
pytest tests/test_integration.py
```

### Code Quality
```bash
# Format code
ruff format .

# Lint code
ruff check .

# Type checking
mypy hazarus/
```

### Running the Framework
```bash
# Initialize project
hazarus init

# Validate scope
hazarus scope validate

# Check privacy
hazarus privacy check

# Run reconnaissance
hazarus recon example.com

# Run network scan
hazarus scan 192.168.1.0/24

# Start dashboard
hazarus dashboard
```

## Configuration Files

- `config/scope.yaml` - Scope configuration (targets, ports, windows)
- `config/hazarus.yaml` - Main framework configuration
- `~/.hazarus/` - User data directory (state, logs, reports)

## External Tools

The framework integrates with the following tools (optional but recommended):

- **Nmap** - Network scanning
- **Anonsurf** - Tor-based anonymity
- **Nikto** - Web server scanning
- **Nuclei** - Vulnerability scanning
- **Semgrep** - Static code analysis
- **Gitleaks** - Secret detection
- **Trivy** - Container/dependency scanning

## Project Structure

```
hazarus/
├── core/              # Core engine and orchestration
├── security/          # Scope, authorization, safety gates
├── anonymity/         # Anonsurf and privacy verification
├── reconnaissance/     # Asset discovery
├── scanning/          # Network and service scanning
├── vulnerability/     # Vulnerability assessment
├── exploitation/      # Exploitation subsystem
├── post_assessment/   # Post-exploitation audits
├── code_analysis/     # Source code analysis
├── reporting/         # Report generation
├── dashboard/         # Web dashboard
├── integrations/      # External tool integrations
├── config/            # Configuration files
├── tests/             # Test suite
├── scripts/           # Utility scripts
└── docs/              # Documentation
```

## Dependencies

See `requirements.txt` for Python dependencies. Key dependencies include:
- typer (CLI)
- pydantic (Validation)
- rich (Terminal UI)
- fastapi (Web API)
- httpx (HTTP client)
- cryptography (Security)
- dnspython (DNS)
- beautifulsoup4 (HTML parsing)

## Security Notes

- All assessments require explicit target authorization
- Scope boundaries are strictly enforced
- Privacy verification is mandatory for assessments
- Exploitation requires lab environment verification
- All operations are logged for audit trails

## Build Process

```bash
# Build for distribution
python -m build

# Create Docker image
docker build -t hazarus:2.0.0 .
```

## Testing Strategy

- Unit tests for individual modules
- Integration tests for component interaction
- End-to-end tests for complete workflows
- Security tests for safety controls
