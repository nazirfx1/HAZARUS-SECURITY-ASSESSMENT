# HAZARUS Security Risk Register

**Created:** 2025-01-01
**Framework Version:** 2.0.0
**Status:** Active

---

## Risk Classification

**CRITICAL:** Could lead to unauthorized access, data loss, or security bypass
**HIGH:** Could compromise assessment integrity or lead to incorrect results
**MEDIUM:** Could affect functionality or user experience
**LOW:** Minor issues with workarounds available

---

## Security Risks

### RISK-001: Scope Enforcement Bypass
**Severity:** CRITICAL
**Status:** OPEN
**Phase:** 3 - Security and Authorization
**File:** security/scope.py
**Description:**
Incomplete validation logic in scope.py (6 pass statements) could allow targets outside authorized scope to be assessed. Scope enforcement is a mandatory security boundary.

**Attack Vector:**
- Attacker could craft targets that bypass incomplete CIDR validation
- Assessment window enforcement incomplete could allow testing outside approved times
- Rate limit gaps could allow unbounded scanning

**Impact:**
- Unauthorized system scanning
- Testing outside approved windows
- Potential legal liability
- Violation of authorization boundaries

**Mitigation:**
- Complete all validation methods in security/scope.py
- Add integration tests to verify scope cannot be bypassed
- Implement default-deny behavior
- Add audit logging for all scope checks

**Acceptance Criteria:**
- [ ] All validation methods implemented
- [ ] Scope bypass tests pass
- [ ] Audit logging verified
- [ ] Default-deny enforced

---

### RISK-002: Safety Gate Bypass
**Severity:** CRITICAL
**Status:** OPEN
**Phase:** 3 - Security and Authorization
**File:** security/safety_gate.py
**Description:**
Incomplete safety gate evaluation (1 pass statement) could allow unsafe operations to proceed without proper checks.

**Attack Vector:**
- Operations could bypass safety checks
- Exploitation could proceed without lab verification
- Assessments could proceed without privacy verification

**Impact:**
- Unauthorized exploitation
- Assessments without privacy controls
- Potential for unauthorized access

**Mitigation:**
- Complete safety gate evaluation logic
- Ensure all operations pass through safety gate
- Add security tests to verify gate cannot be bypassed
- Implement default-deny behavior

**Acceptance Criteria:**
- [ ] Safety gate evaluation implemented
- [ ] All operations route through gate
- [ ] Security tests pass
- [ ] Default-deny enforced

---

### RISK-003: Anonymity False Positive
**Severity:** HIGH
**Status:** OPEN
**Phase:** 6 - Anonymity and Network Routing
**File:** anonymity/anonsurf.py
**Description:**
Anonsurf status check may return positive while actual Tor routing is not working. Tools may bypass proxy settings, making direct connections.

**Attack Vector:**
- User may believe they are anonymous when they are not
- DNS leaks could expose identity
- IPv6 traffic could bypass Tor
- Tools may ignore proxy settings

**Impact:**
- User identity exposure
- Attribution of assessments
- Potential legal consequences
- Violation of privacy expectations

**Mitigation:**
- Implement actual Tor routing verification
- Add tool-specific proxy compatibility checks
- Verify DNS resolution through Tor
- Detect IPv6 exposure
- Implement evidence-based privacy reporting

**Acceptance Criteria:**
- [ ] Tor routing verified
- [ ] Tool proxy compatibility checked
- [ ] DNS leak detection works
- [ ] IPv6 exposure detected
- [ ] Privacy report evidence-based

---

### RISK-004: Proxy Bypass
**Severity:** HIGH
**Status:** OPEN
**Phase:** 6 - Anonymity and Network Routing
**Description:**
Proxy configuration is checked but not enforced. External tools may make direct connections bypassing configured proxy.

**Attack Vector:**
- Tools called without proxy arguments
- HTTP clients may ignore system proxy
- DNS queries may bypass proxy
- IPv6 traffic may bypass proxy

**Impact:**
- Direct connections when proxy expected
- Identity exposure
- Privacy violations
- Attribution of assessments

**Mitigation:**
- Pass proxy arguments to all external tools
- Verify proxy settings for each tool
- Identify tools that cannot use proxies
- Implement configurable routing policies
- Stop operations when routing policy cannot be satisfied

**Acceptance Criteria:**
- [ ] Proxy arguments passed to all tools
- [ ] Proxy settings verified per tool
- [ ] Tools without proxy support identified
- [ ] Routing policies configurable
- [ ] Operations stop on routing failure

---

### RISK-005: Dashboard Authentication Missing
**Severity:** HIGH
**Status:** OPEN
**Phase:** 7 - Dashboard Completion
**File:** dashboard/backend/main.py
**Description:**
FastAPI backend has no authentication or CSRF protection. In-memory storage is not production-ready.

**Attack Vector:**
- Unauthorized access to dashboard
- CSRF attacks on state-changing operations
- Data loss from in-memory storage
- Unauthorized assessment modification

**Impact:**
- Unauthorized access to assessment data
- CSRF attacks
- Data loss
- Unauthorized system modification

**Mitigation:**
- Implement authentication (JWT or session-based)
- Implement role-based authorization
- Add CSRF protection for state-changing operations
- Implement persistent database (SQLAlchemy)
- Secure session management

**Acceptance Criteria:**
- [ ] Authentication implemented
- [ ] Role-based authorization implemented
- [ ] CSRF protection implemented
- [ ] Persistent database configured
- [ ] Session management secure

---

### RISK-006: Unvalidated Subprocess Arguments
**Severity:** MEDIUM
**Status:** MITIGATED
**Phase:** All
**Description:**
Audit found no shell=True usage and proper argument lists in subprocess calls. However, input validation should be verified.

**Attack Vector:**
- User input not validated before subprocess execution
- Path traversal in file operations
- Command injection through argument injection

**Impact:**
- Command injection
- Unauthorized file access
- System compromise

**Mitigation:**
- ✅ No shell=True usage found
- ✅ All subprocess calls use argument lists
- [ ] Add input validation tests
- [ ] Verify path sanitization
- [ ] Add argument validation

**Acceptance Criteria:**
- [x] No shell=True usage
- [x] Proper subprocess usage
- [ ] Input validation tests added
- [ ] Path sanitization verified
- [ ] Argument validation added

---

### RISK-007: Credential Exposure in Logs
**Severity:** MEDIUM
**Status:** OPEN
**Phase:** All
**Description:**
Audit logging may inadvertently log sensitive information including credentials, API keys, or assessment details.

**Attack Vector:**
- Logs may contain credentials
- Audit logs may expose sensitive data
- Error messages may leak information

**Impact:**
- Credential exposure
- Sensitive data exposure
- Information leakage

**Mitigation:**
- Implement log sanitization
- Redact credentials from logs
- Sensitive data masking
- Secure log storage

**Acceptance Criteria:**
- [ ] Log sanitization implemented
- [ ] Credentials redacted from logs
- [ ] Sensitive data masked
- [ ] Secure log storage

---

### RISK-008: Hardcoded Secrets
**Severity:** LOW
**Status:** MITIGATED
**Phase:** All
**Description:**
Audit found no hardcoded passwords or credentials in source code.

**Attack Vector:**
- Secrets in source code
- API keys in configuration
- Credentials in reports

**Impact:**
- Credential exposure
- Unauthorized access
- System compromise

**Mitigation:**
- ✅ No hardcoded passwords found
- ✅ No hardcoded API keys found
- [ ] Verify no secrets in configuration files
- [ ] Verify no secrets in reports
- [ ] Add secret scanning to CI

**Acceptance Criteria:**
- [x] No hardcoded passwords
- [x] No hardcoded API keys
- [ ] Configuration files verified
- [ ] Reports verified
- [ ] Secret scanning in CI

---

### RISK-009: Unsafe External Tool Execution
**Severity:** MEDIUM
**Status:** MITIGATED
**Phase:** All
**Description:**
External tools (nmap, nikto, nuclei, etc.) are executed without verifying they are in authorized lab environments for exploitation.

**Attack Vector:**
- Exploitation against non-lab targets
- Tools executed against unauthorized systems
- Lab verification bypass

**Impact:**
- Unauthorized exploitation
- System damage
- Legal liability

**Mitigation:**
- ✅ Lab executor checks target CIDR
- ✅ Exploit engine requires lab verification
- [ ] All exploitation tools check lab environment
- [ ] Integration tests for lab enforcement
- [ ] Audit logging for all exploitation

**Acceptance Criteria:**
- [x] Lab executor checks CIDR
- [x] Exploit engine requires lab
- [ ] All tools check lab environment
- [ ] Lab enforcement tests pass
- [ ] Audit logging verified

---

### RISK-010: Insufficient Test Coverage
**Severity:** HIGH
**Status:** OPEN
**Phase:** 8 - Testing
**Description:**
Only 14 tests for 86 Python files (~5% coverage). Security components lack sufficient testing.

**Attack Vector:**
- Undetected security vulnerabilities
- Bypass of safety controls
- Scope enforcement failures
- Privacy verification failures

**Impact:**
- Security vulnerabilities in production
- Unauthorized access
- Privacy violations
- System compromise

**Mitigation:**
- Expand test suite to 70%+ coverage
- Add security validation tests
- Add scope bypass tests
- Add privacy verification tests
- Add Metasploit RPC mocked tests

**Acceptance Criteria:**
- [ ] 70%+ overall coverage
- [ ] 90%+ security component coverage
- [ ] Security validation tests pass
- [ ] Scope bypass tests pass
- [ ] Privacy verification tests pass

---

## Operational Risks

### RISK-011: Installation Script Failure
**Severity:** MEDIUM
**Status:** OPEN
**Phase:** 9 - Installation and Parrot OS
**File:** install.sh
**Description:**
Installation script has not been tested on Parrot OS. May fail on package installation or dependency resolution.

**Impact:**
- Installation failure
- User frustration
- Platform incompatibility

**Mitigation:**
- Test on clean Parrot OS
- Add error handling
- Add dependency checks
- Provide manual installation fallback

**Acceptance Criteria:**
- [ ] Tested on Parrot OS
- [ ] Error handling added
- [ ] Dependency checks added
- [ ] Manual fallback documented

---

### RISK-012: PDF Generation Failure
**Severity:** LOW
**Status:** OPEN
**Phase:** 5 - Module Completion
**File:** reporting/pdf_report.py
**Description:**
PDF generation requires reportlab and weasyprint which may fail on some systems. No fallback if PDF generation fails.

**Impact:**
- Report generation failure
- User frustration
- Incomplete assessment delivery

**Mitigation:**
- Add error handling for PDF generation
- Provide fallback to HTML/JSON
- Document PDF dependencies
- Test on target platforms

**Acceptance Criteria:**
- [ ] Error handling added
- [ ] Fallback implemented
- [ ] Dependencies documented
- [ ] Tested on platforms

---

### RISK-013: External Tool Unavailability
**Severity:** LOW
**Status:** MITIGATED
**Phase:** All
**Description:**
External tools (nmap, nikto, nuclei, etc.) may not be installed or may not be available on target platform.

**Impact:**
- Feature unavailability
- Assessment limitations
- User confusion

**Mitigation:**
- ✅ Tools marked as optional
- ✅ Availability checks implemented
- ✅ Graceful degradation
- [ ] Clear error messages
- [ ] Installation guidance

**Acceptance Criteria:**
- [x] Tools optional
- [x] Availability checks
- [x] Graceful degradation
- [ ] Clear error messages
- [ ] Installation guidance

---

## Summary

**Total Risks:** 13
**Critical:** 2
**High:** 4
**Medium:** 5
**Low:** 2

**Open Risks:** 11
**Mitigated Risks:** 2

**Risk Exposure:** HIGH

---

## Risk Mitigation Priority

1. **RISK-001:** Scope Enforcement Bypass (CRITICAL)
2. **RISK-002:** Safety Gate Bypass (CRITICAL)
3. **RISK-003:** Anonymity False Positive (HIGH)
4. **RISK-004:** Proxy Bypass (HIGH)
5. **RISK-005:** Dashboard Authentication Missing (HIGH)
6. **RISK-010:** Insufficient Test Coverage (HIGH)

---

## Progress Tracking

| Risk ID | Status | Mitigation | Tests | Remaining |
|-------|--------|-----------|-------|-----------|
| RISK-001 | OPEN | NOT STARTED | NOT STARTED | 4h |
| RISK-002 | OPEN | NOT STARTED | NOT STARTED | 2h |
| RISK-003 | OPEN | NOT STARTED | NOT STARTED | 4h |
| RISK-004 | OPEN | NOT STARTED | NOT STARTED | 3h |
| RISK-005 | OPEN | NOT STARTED | NOT STARTED | 8h |
| RISK-006 | MITIGATED | COMPLETE | NOT STARTED | 1h |
| RISK-007 | OPEN | NOT STARTED | NOT STARTED | 2h |
| RISK-008 | MITIGATED | COMPLETE | NOT STARTED | 1h |
| RISK-009 | MITIGATED | COMPLETE | NOT STARTED | 2h |
| RISK-010 | OPEN | NOT STARTED | NOT STARTED | 16h |
| RISK-011 | OPEN | NOT STARTED | NOT STARTED | 4h |
| RISK-012 | OPEN | NOT STARTED | NOT STARTED | 1h |
| RISK-013 | MITIGATED | COMPLETE | NOT STARTED | 1h |

**Hours Spent:** 0
**Hours Remaining:** 48
