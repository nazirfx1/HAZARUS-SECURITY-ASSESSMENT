# HAZARUS Critical Work Completion Plan

**Created:** 2025-01-01
**Framework Version:** 2.0.0
**Estimated Total Effort:** 85 hours

---

## Priority 1: Phase 3 - Security & Authorization (CRITICAL)

**Estimated Effort:** 6 hours
**Risk:** CRITICAL - Scope enforcement bypass possible without completion

### Task 3.1: Complete security/scope.py Validation Methods
**Estimated Effort:** 4 hours
**Files:** security/scope.py

**Incomplete Methods (6 pass statements):**

1. **Line 19: __init__ validation**
   - Implement validation of configuration fields
   - Validate CIDR syntax
   - Validate port ranges
   - Validate intensity level
   - **Acceptance:** Configuration validated on load

2. **Line 146: CIDR validation**
   - Implement validate_cidr(cidr: str) -> bool
   - Parse IPv4 and IPv6 CIDR
   - Validate CIDR syntax
   - Store parsed networks for quick lookup
   - **Acceptance:** CIDR validation works for IPv4 and IPv6

3. **Line 153: Port validation**
   - Implement validate_port(port: int) -> bool
   - Check against allowed_ports list
   - Validate port range syntax (e.g., "1-1000", "22,80,443")
   - **Acceptance:** Port validation enforced

4. **Line 160: Assessment window validation**
   - Implement validate_assessment_window() -> bool
   - Check current time against assessment_window
   - Validate start_time and end_time format
   - Return False if outside window
   - **Acceptance:** Assessments blocked outside approved windows

5. **Line 196: Rate limit validation**
   - Implement check_rate_limit() -> bool
   - Track request count per time window
   - Return False if rate_limit exceeded
   - **Acceptance:** Rate limiting enforced

6. **Line 231: Concurrency validation**
   - Implement check_concurrency() -> bool
   - Track active assessments
   - Return False if max concurrent assessments exceeded
   - **Acceptance:** Concurrency limits enforced

**Implementation Steps:**
1. Read security/scope.py to understand current structure
2. Implement each validation method with proper error handling
3. Add logging for validation failures
4. Add unit tests for each validation method
5. Add integration tests for scope bypass attempts
6. Run tests and fix any issues

### Task 3.2: Complete security/safety_gate.py Evaluation
**Estimated Effort:** 2 hours
**Files:** security/safety_gate.py

**Incomplete Method (1 pass statement):**

1. **Line 16: evaluate method**
   - Implement evaluate(operation: str, context: Dict) -> bool
   - Check operation against policy rules
   - Check operator permissions
   - Check scope authorization
   - Return True if operation allowed, False otherwise
   - **Acceptance:** All operations pass through safety gate

**Implementation Steps:**
1. Read security/safety_gate.py to understand structure
2. Implement evaluate() with policy checking
3. Add integration with policy_engine.py
4. Add logging for gate decisions
5. Add unit tests for gate evaluation
6. Run tests and fix any issues

---

## Priority 2: Phase 5 - Module Completion (HIGH)

**Estimated Effort:** 20 hours
**Risk:** HIGH - Incomplete functionality across modules

### Task 5.1: Complete Reconnaissance Modules
**Estimated Effort:** 4 hours
**Files:** reconnaissance/dns.py, reconnaissance/subdomains.py

**Incomplete Methods (7 pass statements):**

**reconnaissance/dns.py (5 pass statements):**
1. Line 116: TXT record query
2. Line 130: MX record query
3. Line 142: NS record query
4. Line 169: SRV record query
5. Line 199: CAA record query

**reconnaissance/subdomains.py (2 pass statements):**
1. Line 118: Amass integration
2. Line 131: Subfinder integration

**Implementation:**
- Implement DNS record type queries using dnspython
- Add error handling for DNS failures
- Implement optional Amass integration (check if installed)
- Implement optional Subfinder integration (check if installed)
- Add rate limiting for DNS queries
- Add tests for each method

### Task 5.2: Complete Scanning Modules
**Estimated Effort:** 3 hours
**Files:** scanning/api_discovery.py

**Incomplete Methods (5 pass statements):**
1. Line 128: OpenAPI parsing
2. Line 131: GraphQL endpoint detection
3. Line 172: Rate limit detection
4. Line 207: Authentication detection
5. Line 227: Authorization testing

**Implementation:**
- Implement OpenAPI/Swagger JSON parsing
- Implement GraphQL endpoint detection (query introspection)
- Implement rate limit detection from headers
- Implement authentication scheme detection
- Implement basic authorization testing
- Add tests for each method

### Task 5.3: Complete Vulnerability Modules
**Estimated Effort:** 1 hour
**Files:** vulnerability/exploitdb.py

**Incomplete Methods (1 pass statement):**
1. Line 98: Query execution

**Implementation:**
- Implement Exploit-DB API query
- Add rate limiting
- Add error handling
- Add tests

### Task 5.4: Complete Post-Assessment Modules
**Estimated Effort:** 12 hours
**Files:** 4 post_assessment modules

**post_assessment/privilege_audit.py (4 pass statements):**
1. Line 113: Windows service permissions
2. Line 148: Windows privilege assignments
3. Line 174: Windows scheduled tasks
4. Line 204: Windows autorun checks

**post_assessment/credential_exposure.py (4 pass statements):**
1. Line 101: SSH key scanning
2. Line 132: Browser credential check
3. Line 163: Application credential check
4. Line 185: Registry credential check

**post_assessment/lateral_movement_audit.py (3 pass statements):**
1. Line 118: Cached credential analysis
2. Line 145: Windows AD configuration
3. Line 150: SMB security review

**post_assessment/persistence_audit.py (4 pass statements):**
1. Line 113: User systemd services
2. Line 148: Cron job analysis
3. Line 174: Startup file analysis
4. Line 204: Profile file analysis

**Implementation:**
- Implement Windows-specific privilege checks (platform detection)
- Implement credential exposure checks (safe, don't expose actual credentials)
- Implement lateral movement checks (network segmentation, trust relationships)
- Implement persistence detection (systemd, cron, scheduled tasks, registry)
- Add cross-platform detection logic
- Add tests for each method
- **Note:** Windows-specific methods can return "not applicable" on Linux

---

## Priority 3: Phase 8 - Testing (HIGH)

**Estimated Effort:** 24 hours
**Risk:** HIGH - Insufficient test coverage, no security tests

### Task 8.1: Add Security Validation Tests
**Estimated Effort:** 6 hours
**Files:** tests/test_security_validation.py (new)

**Test Cases:**
1. Scope validation bypass attempts
2. CIDR validation (IPv4 and IPv6)
3. Port range validation
4. Assessment window enforcement
5. Rate limiting enforcement
6. Concurrency limits
7. Safety gate evaluation
8. Policy engine evaluation
9. Authorization expiration
10. Emergency stop functionality

**Implementation:**
- Create tests/test_security_validation.py
- Add tests for each security component
- Add tests for bypass attempts
- Add tests for edge cases
- Target: 90%+ coverage for security components

### Task 8.2: Add CLI Integration Tests
**Estimated Effort:** 4 hours
**Files:** tests/test_cli.py (new)

**Test Cases:**
1. hazarus init
2. hazarus scope validate
3. hazarus privacy check
4. hazarus recon (with valid/invalid targets)
5. hazarus scan (with valid/invalid targets)
6. hazarus web
7. hazarus research
8. hazarus exploit list
9. hazarus exploit inspect
10. hazarus report
11. hazarus update

**Implementation:**
- Create tests/test_cli.py
- Use typer.testing CliRunner
- Test exit codes
- Test error messages
- Test scope validation in CLI

### Task 8.3: Add Module Integration Tests
**Estimated Effort:** 8 hours
**Files:** tests/test_module_integration.py (new)

**Test Cases:**
1. DNS reconnaissance integration
2. WHOIS integration
3. Nmap scanning integration
4. HTTP scanning integration
5. CVSS calculation
6. CVE matching
7. Exploit registry
8. Evidence manager
9. Report generation
10. Dashboard API

**Implementation:**
- Create tests/test_module_integration.py
- Test module interactions
- Mock external tools for CI
- Test error handling
- Test scope enforcement in modules

### Task 8.4: Add Mocked External Tool Tests
**Estimated Effort:** 4 hours
**Files:** tests/test_external_tools.py (new)

**Test Cases:**
1. Nmap execution (mocked)
2. Nikto execution (mocked)
3. Nuclei execution (mocked)
4. Semgrep execution (mocked)
5. Gitleaks execution (mocked)
6. Trivy execution (mocked)
7. Metasploit RPC (mocked)

**Implementation:**
- Create tests/test_external_tools.py
- Use unittest.mock for subprocess calls
- Test argument construction
- Test error handling
- Test output parsing

### Task 8.5: Measure and Improve Coverage
**Estimated Effort:** 2 hours

**Implementation:**
- Run pytest with --cov
- Generate coverage report
- Identify uncovered code paths
- Add tests for uncovered paths
- Target: 70%+ overall coverage

---

## Priority 4: Phase 6 - Anonymity & Network Routing (HIGH)

**Estimated Effort:** 7 hours
**Risk:** HIGH - Anonymity false positives, proxy bypass

### Task 6.1: Implement Routing Verification Service
**Estimated Effort:** 4 hours
**Files:** anonymity/routing_verification.py (new)

**Components:**
1. Actual Tor routing verification
2. DNS leak detection enhancement
3. IPv6 exposure detection enhancement
4. Tool-specific proxy compatibility checks
5. Routing policy configuration

**Implementation:**
- Create centralized routing verification service
- Implement actual Tor exit IP check (via external API)
- Implement DNS resolution through Tor
- Check each external tool's proxy configuration
- Define routing policies (Normal, Proxy, Tor modes)
- Add tests

### Task 6.2: Implement Proxy Enforcement
**Estimated Effort:** 3 hours
**Files:** All scanning/vulnerability modules

**Components:**
1. Pass proxy arguments to all external tools
2. Verify proxy settings per tool
3. Identify tools that cannot use proxies
4. Stop operations when routing policy fails

**Implementation:**
- Add proxy configuration to module constructors
- Pass proxy arguments to subprocess calls
- Add proxy compatibility checks
- Add tests

---

## Priority 5: Phase 7 - Dashboard Completion (HIGH)

**Estimated Effort:** 16 hours
**Risk:** HIGH - No authentication, insecure by default

### Task 7.1: Implement Dashboard Authentication
**Estimated Effort:** 8 hours
**Files:** dashboard/backend/main.py

**Components:**
1. JWT-based authentication
2. User authentication (username/password)
3. Token generation and validation
4. Protected routes
5. Login/logout endpoints

**Implementation:**
- Add JWT dependency (python-jose)
- Implement auth endpoints (/login, /logout)
- Add authentication middleware
- Protect state-changing endpoints
- Add tests

### Task 7.2: Implement Role-Based Authorization
**Estimated Effort:** 3 hours
**Files:** dashboard/backend/main.py

**Components:**
1. Role definitions (admin, operator, viewer)
2. Permission checking
3. Role-based route protection

**Implementation:**
- Define roles and permissions
- Implement permission checking middleware
- Apply to dashboard routes
- Add tests

### Task 7.3: Implement CSRF Protection
**Estimated Effort:** 2 hours
**Files:** dashboard/backend/main.py

**Components:**
1. CSRF token generation
2. CSRF token validation
3. Apply to state-changing endpoints

**Implementation:**
- Add CSRF middleware
- Generate tokens for forms
- Validate tokens on POST/PUT/DELETE
- Add tests

### Task 7.4: Implement Persistent Database
**Estimated Effort:** 3 hours
**Files:** dashboard/backend/main.py

**Components:**
1. SQLAlchemy models
2. Database initialization
3. Replace in-memory storage

**Implementation:**
- Create SQLAlchemy models for assessments, findings, users
- Initialize database on startup
- Replace in-memory dict storage with database
- Add migration support
- Add tests

---

## Priority 6: Phase 9 - Installation & Parrot OS (MEDIUM)

**Estimated Effort:** 4 hours
**Risk:** MEDIUM - Installation may fail on Parrot OS

### Task 9.1: Test Installation on Parrot OS
**Estimated Effort:** 2 hours
**Files:** install.sh

**Components:**
1. Python version check
2. Virtual environment creation
3. Dependency installation
4. External tool detection
5. Installation verification

**Implementation:**
- Add Python version check (>=3.11)
- Add venv creation
- Add dependency installation with error handling
- Add external tool availability checks
- Add installation verification steps
- Test on Parrot OS (VM or actual)

### Task 9.2: Add Error Handling to Installation
**Estimated Effort:** 1 hour
**Files:** install.sh

**Implementation:**
- Add try/catch blocks
- Add clear error messages
- Add fallback to manual installation
- Add dependency troubleshooting guide

### Task 9.3: Document Installation Issues
**Estimated Effort:** 1 hour
**Files:** docs/INSTALLATION.md (new)

**Implementation:**
- Create installation guide
- Document common issues
- Document manual installation steps
- Document external tool installation

---

## Priority 7: Phase 10 - Release Engineering (MEDIUM)

**Estimated Effort:** 8 hours
**Risk:** MEDIUM - Documentation incomplete

### Task 10.1: Create Release Documentation
**Estimated Effort:** 4 hours
**Files:** CHANGELOG.md, CONTRIBUTING.md, SECURITY.md, LICENSE

**Implementation:**
- Create CHANGELOG.md with version history
- Create CONTRIBUTING.md with contribution guidelines
- Create SECURITY.md with security policy
- Add LICENSE file (MIT)
- Update README.md to match actual capabilities

### Task 10.2: Create Technical Documentation
**Estimated Effort:** 4 hours
**Files:** docs/INSTALLATION.md, docs/CLI_REFERENCE.md, docs/ARCHITECTURE.md, docs/TROUBLESHOOTING.md

**Implementation:**
- Create docs/INSTALLATION.md
- Create docs/CLI_REFERENCE.md (document all CLI commands)
- Create docs/ARCHITECTURE.md (document system architecture)
- Create docs/TROUBLESHOOTING.md (common issues and solutions)

---

## Execution Schedule

### Sprint 1: Critical Security (6 hours)
**Goal:** Address CRITICAL security risks
- Task 3.1: Complete security/scope.py (4 hours)
- Task 3.2: Complete security/safety_gate.py (2 hours)
- **Deliverable:** Security validation complete, scope bypass tests passing

### Sprint 2: Module Completion (20 hours)
**Goal:** Complete all pass statements in modules
- Task 5.1: Complete reconnaissance modules (4 hours)
- Task 5.2: Complete scanning modules (3 hours)
- Task 5.3: Complete vulnerability modules (1 hour)
- Task 5.4: Complete post-assessment modules (12 hours)
- **Deliverable:** All 28 pass statements implemented

### Sprint 3: Testing (24 hours)
**Goal:** Achieve 70%+ test coverage
- Task 8.1: Security validation tests (6 hours)
- Task 8.2: CLI integration tests (4 hours)
- Task 8.3: Module integration tests (8 hours)
- Task 8.4: Mocked external tool tests (4 hours)
- Task 8.5: Coverage measurement (2 hours)
- **Deliverable:** 70%+ coverage, all security tests passing

### Sprint 4: Anonymity & Dashboard (23 hours)
**Goal:** Complete anonymity verification and dashboard security
- Task 6.1: Routing verification service (4 hours)
- Task 6.2: Proxy enforcement (3 hours)
- Task 7.1: Dashboard authentication (8 hours)
- Task 7.2: Role-based authorization (3 hours)
- Task 7.3: CSRF protection (2 hours)
- Task 7.4: Persistent database (3 hours)
- **Deliverable:** Anonymity verified, dashboard secured

### Sprint 5: Release Engineering (12 hours)
**Goal:** Prepare for production release
- Task 9.1: Test installation on Parrot OS (2 hours)
- Task 9.2: Installation error handling (1 hour)
- Task 9.3: Installation documentation (1 hour)
- Task 10.1: Release documentation (4 hours)
- Task 10.2: Technical documentation (4 hours)
- **Deliverable:** Installation verified, documentation complete

---

## Acceptance Criteria per Sprint

### Sprint 1 Acceptance
- [ ] All 6 pass statements in security/scope.py implemented
- [ ] 1 pass statement in security/safety_gate.py implemented
- [ ] Security validation tests pass
- [ ] Scope bypass tests pass
- [ ] No CRITICAL security risks remain

### Sprint 2 Acceptance
- [ ] All 28 pass statements across modules implemented
- [ ] All modules have complete implementations
- [ ] Module tests pass
- [ ] No incomplete methods remain

### Sprint 3 Acceptance
- [ ] 70%+ overall test coverage achieved
- [ ] 90%+ security component coverage achieved
- [ ] All security tests pass
- [ ] All CLI integration tests pass
- [ ] All module integration tests pass

### Sprint 4 Acceptance
- [ ] Routing verification service implemented
- [ ] Proxy enforcement implemented
- [ ] Dashboard authentication implemented
- [ ] Dashboard CSRF protection implemented
- [ ] Dashboard uses persistent database
- [ ] Anonymity verification evidence-based

### Sprint 5 Acceptance
- [ ] Installation tested on Parrot OS
- [ ] Installation script has error handling
- [ ] All release documentation created
- [ ] README updated to match actual capabilities
- [ ] LICENSE file added
- [ ] Framework ready for production use

---

## Total Effort Summary

| Sprint | Hours | Priority | Status |
|--------|-------|----------|--------|
| Sprint 1 | 6 | CRITICAL | NOT STARTED |
| Sprint 2 | 20 | HIGH | NOT STARTED |
| Sprint 3 | 24 | HIGH | NOT STARTED |
| Sprint 4 | 23 | HIGH | NOT STARTED |
| Sprint 5 | 12 | MEDIUM | NOT STARTED |
| **Total** | **85** | | |

---

## Blockers and Dependencies

### Sprint 1 Dependencies
- None - Can start immediately

### Sprint 2 Dependencies
- Depends on Sprint 1 (no dependencies actually, but logical order)

### Sprint 3 Dependencies
- Depends on Sprint 2 (modules must be complete to test them)
- Depends on Sprint 1 (security tests need complete validation)

### Sprint 4 Dependencies
- Depends on Sprint 1 (security tests need complete validation)
- Depends on Sprint 2 (dashboard needs modules to be functional)

### Sprint 5 Dependencies
- Depends on Sprint 4 (installation verification needs stable codebase)
- Depends on Sprint 3 (documentation needs to reflect final state)

---

## Risk Mitigation

### Risk: Scope Validation Complexity
**Mitigation:** Start with simple validation, add edge cases iteratively
**Contingency:** Use ipaddress library for robust CIDR parsing

### Risk: Windows-Specific Code on Linux
**Mitigation:** Add platform detection, return "not applicable" on wrong platform
**Contingency:** Use Linux-only tests, mock Windows paths

### Risk: External Tool Installation
**Mitigation:** Make all external tools optional, graceful degradation
**Contingency:** Document manual installation steps

### Risk: Test Coverage Target Not Met
**Mitigation:** Focus on critical paths first, add tests iteratively
**Contingency:** Accept 60% coverage if 70% requires excessive effort

### Risk: Dashboard Authentication Complexity
**Mitigation:** Use proven libraries (python-jose), follow best practices
**Contingency:** Start with basic auth, add RBAC in later iteration

---

## Success Metrics

### Before Starting
- Test coverage: ~5%
- Security tests: 0
- CLI commands wired: 9/17
- Pass statements: 32
- Security risks: 2 CRITICAL, 4 HIGH

### After Completion
- Test coverage: 70%+
- Security tests: 20+
- CLI commands wired: 17/17
- Pass statements: 0
- Security risks: 0 CRITICAL, 0 HIGH

---

## Next Steps

1. **Immediate:** Start Sprint 1 (Critical Security)
2. **After Sprint 1:** Start Sprint 2 (Module Completion)
3. **After Sprint 2:** Start Sprint 3 (Testing)
4. **After Sprint 3:** Start Sprint 4 (Anonymity & Dashboard)
5. **After Sprint 4:** Start Sprint 5 (Release Engineering)

**Estimated Timeline:** 5-7 working days (assuming 8-12 hours per day)

---

**Plan Created:** 2025-01-01
**Ready for Execution:** YES
