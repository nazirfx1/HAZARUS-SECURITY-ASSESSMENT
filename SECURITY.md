# Security Policy

## Supported Versions

Current stable version: 2.0.0

## Reporting a Vulnerability

If you discover a security vulnerability in HAZARUS, please report it responsibly.

**DO NOT:**
- Open a public issue
- Discuss the vulnerability in public forums
- Exploit the vulnerability

**DO:**
- Send an email to: security@hazarus.local
- Include details about the vulnerability
- Provide proof of concept (if possible)
- Allow us time to fix before disclosure

## Security Features

### Authorization & Scope Enforcement
- All assessments require explicit target authorization
- Scope boundaries are strictly enforced
- Unauthorized targets are blocked

### Privacy Protection
- Mandatory privacy verification before assessments
- Anonsurf/Tor integration for anonymity
- DNS leak detection
- IPv6 exposure checks

### Exploitation Controls
- Exploitation requires lab environment verification
- Only allowed in authorized/lab environments
- Controlled exploit execution
- No uncontrolled payload execution

### Audit Logging
- All operations are logged for audit trails
- Operator ID tracking
- Assessment window enforcement
- Rate limiting

## Security Best Practices

### For Users
1. Always use in authorized environments only
2. Keep the framework updated
3. Use Tor/Anonsurf for anonymity when required
4. Review scope configuration before assessments
5. Never commit scope.yaml to public repositories
6. Rotate credentials regularly
7. Use sudo only when necessary
8. Review audit logs regularly

### For Operators
1. Maintain proper authorization documentation
2. Follow ethical hacking guidelines
3. Obtain written permission before assessments
4. Report findings responsibly
5. Maintain chain of custody for evidence
6. Use secure communication channels
7. Follow disclosure policies

## Scope Configuration

The `config/scope.yaml` file contains sensitive information:
- Allowed targets
- Assessment windows
- Operator credentials
- Emergency contacts

**NEVER commit this file to version control.** It is already in `.gitignore`.

## Data Protection

### Sensitive Data Locations
- `~/.hazarus/` - User data directory
- `~/.hazarus/reports/` - Assessment reports
- `~/.hazarus/evidence/` - Collected evidence
- `~/.hazarus/logs/` - Activity logs

### Data Retention
- Review and clean old reports regularly
- Securely delete sensitive evidence
- Audit log retention policy per organization

## External Tool Security

HAZARUS integrates with external security tools. Ensure:
- Tools are from trusted sources
- Tools are kept updated
- Tool execution is authorized
- Tool outputs are reviewed

## License

HAZARUS is for authorized security assessments only. Misuse is prohibited.

## Contact

For security-related questions:
- Email: security@hazarus.local
- Issues: Use the "Security" label on GitHub
