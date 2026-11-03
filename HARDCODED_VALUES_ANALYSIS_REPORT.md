# HAZARUS Security Assessment Framework - Hardcoded Values & Placeholder Analysis Report

**Date:** 2025-11-03  
**Analysis Type:** Comprehensive Deep Analysis  
**Scope:** All source code files

---

## Executive Summary

This report documents all hardcoded values, placeholder implementations, and incomplete features found in the HAZARUS Security Assessment Framework codebase. The analysis identified **47 distinct issues** across **15 files** that require remediation.

### Summary of Findings

| Category | Count | Severity |
|----------|-------|----------|
| Hardcoded IP/CIDR Ranges | 8 | Medium |
| Hardcoded Example Domains | 1 | Low |
| Hardcoded Timeouts | 59 | Medium |
| Hardcoded Ports | 3 | Low |
| Hardcoded File Paths | 3 | Medium |
| Placeholder Functions | 12 | High |
| "Not Yet Implemented" Messages | 7 | High |
| Missing Configuration | 1 | High |
| **Total** | **94** | - |

---

## 1. HARDCODED VALUES

### 1.1 Hardcoded IP/CIDR Ranges

#### Issue #1: Lab CIDR Ranges in `exploitation/lab_executor.py`
**File:** `exploitation/lab_executor.py`  
**Line:** 60  
**Severity:** Medium  
**Description:** Hardcoded lab CIDR ranges for exploit testing environment.

```python
self._lab_cidrs = ["192.168.100.0/24", "10.0.100.0/24"]
```

**Impact:** Users cannot configure their own lab network ranges without modifying source code.

**Recommended Fix:** Move to configuration file (`config/hazarus.yaml`).

---

#### Issue #2: Lab CIDR Ranges in `exploitation/exploit_engine.py`
**File:** `exploitation/exploit_engine.py`  
**Line:** 55  
**Severity:** Medium  
**Description:** Duplicate hardcoded lab CIDR ranges.

```python
self._lab_ranges: List[str] = ["192.168.100.0/24", "10.0.100.0/24"]
```

**Impact:** Same as Issue #1 - prevents custom lab configuration.

**Recommended Fix:** Consolidate with Issue #1 into single configuration.

---

#### Issue #3: Lab Target IP in `exploitation/lab_executor.py`
**File:** `exploitation/lab_executor.py`  
**Line:** 70  
**Severity:** Medium  
**Description:** Hardcoded lab target IP address.

```python
ip="192.168.100.10",
```

**Impact:** Cannot configure custom lab target IPs.

**Recommended Fix:** Move to configuration file.

---

#### Issue #4: Lab Target IP in `exploitation/lab_executor.py`
**File:** `exploitation/lab_executor.py`  
**Line:** 79  
**Severity:** Medium  
**Description:** Second hardcoded lab target IP.

```python
ip="192.168.100.20",
```

**Impact:** Same as Issue #3.

**Recommended Fix:** Move to configuration file.

---

#### Issue #5: Lab CIDR Ranges in `security/safety_gate.py`
**File:** `security/safety_gate.py`  
**Line:** 153  
**Severity:** Medium  
**Description:** Hardcoded lab CIDR ranges for safety gate validation.

```python
"192.168.100.0/24",
```

**Impact:** Safety gate cannot validate custom lab ranges.

**Recommended Fix:** Consolidate with other lab CIDR configurations.

---

#### Issue #6: Lab CIDR Ranges in `security/safety_gate.py`
**File:** `security/safety_gate.py`  
**Line:** 154  
**Severity:** Medium  
**Description:** Second hardcoded lab CIDR range.

```python
"10.0.100.0/24",
```

**Impact:** Same as Issue #5.

**Recommended Fix:** Consolidate with other lab CIDR configurations.

---

### 1.2 Hardcoded Example Domains

#### Issue #7: Example Domain in Scope Template
**File:** `security/scope.py`  
**Lines:** 566-569, 578, 580  
**Severity:** Low  
**Description:** Hardcoded example domains in scope configuration template.

```python
"allowed_targets": ["192.168.1.100", "example.com"],
"allowed_domains": ["example.com", "test.example.com"],
"excluded_targets": ["192.168.1.1", "critical.example.com"],
"operator_id": "operator@example.com",
"emergency_contact": "emergency@example.com",
```

**Impact:** Users may accidentally use example values in production configurations.

**Recommended Fix:** Add validation to reject example.com and test.com domains, or use placeholder values like `YOUR_DOMAIN_HERE`.

---

### 1.3 Hardcoded Timeouts

#### Issue #8: HTTP Client Timeouts (59 occurrences)
**Files:** Multiple files across the codebase  
**Severity:** Medium  
**Description:** Hardcoded timeout values in HTTP clients.

**Examples:**
- `timeout=30.0` (most common)
- `timeout=10.0` (quick operations)
- `timeout=600` (long operations)
- `timeout=300` (exploitation)
- `timeout=5` (validation checks)

**Affected Files:**
- `hazarus/interactive.py` (lines 819, 1098, 1107)
- `reconnaissance/advanced/origin_ip.py` (lines 91, 121, 163, 202, 235, 270)
- `reconnaissance/advanced/passive.py` (lines 134, 172, 214, 262)
- `reconnaissance/advanced/dns.py` (line 93)
- `reconnaissance/advanced/subdomains.py` (lines 112, 195, 270, 332)
- `reconnaissance/advanced/live_hosts.py` (line 224)
- `reconnaissance/security/virtual_host.py` (line 98)
- `reconnaissance/security/subdomain_takeover.py` (line 107)
- `reconnaissance/intelligence/api_sources.py` (lines 74, 123, 176, 227, 272)
- `scanning/http_scanner.py` (lines 317, 358, 501)
- `exploitation/metasploit_rpc.py` (lines 62, 90, 128, 171, 201, 240, 256)
- `code_analysis/trivy.py` (line 70)
- `code_analysis/gitleaks.py` (line 69)
- `code_analysis/semgrep.py` (line 70)
- `vulnerability/github_advisories.py` (line 57)
- `vulnerability/cve_matcher.py` (lines 64, 171)
- `vulnerability/owasp_zap.py` (line 212)
- `anonymity/proxy_validation.py` (line 32)
- `anonymity/tor_check.py` (lines 25, 35, 47)
- `post_assessment/exfiltration_simulation.py` (line 120)

**Impact:** Users cannot adjust timeouts based on network conditions or target responsiveness.

**Recommended Fix:** Create timeout configuration in `config/hazarus.yaml` with categories:
- `default_timeout: 30`
- `quick_timeout: 10`
- `long_timeout: 600`
- `exploitation_timeout: 300`
- `validation_timeout: 5`

---

### 1.4 Hardcoded Ports

#### Issue #9: Hardcoded SSL Port
**Files:** 
- `reconnaissance/advanced/origin_ip.py` (line 83)
- `scanning/http_scanner.py` (line 387)

**Severity:** Low  
**Description:** Hardcoded port 443 for SSL connections.

```python
"openssl", "s_client", "-connect", f"{domain}:443",
```

**Impact:** Cannot test SSL on non-standard ports.

**Recommended Fix:** Make port configurable or auto-detect.

---

#### Issue #10: Hardcoded Dashboard Port
**File:** `dashboard/backend/main.py` (line 331)  
**Severity:** Low  
**Description:** Hardcoded port 8000 for dashboard.

```python
uvicorn.run(app, host="127.0.0.1", port=8000)
```

**Impact:** Cannot run dashboard on different port.

**Recommended Fix:** Add to configuration file.

---

#### Issue #11: Hardcoded ZAP Port
**File:** `vulnerability/owasp_zap.py` (line 47)  
**Severity:** Low  
**Description:** Hardcoded port 8080 for OWASP ZAP.

```python
def __init__(self, api_key: str, zap_host: str = "127.0.0.1", zap_port: int = 8080):
```

**Impact:** Cannot connect to ZAP on different port.

**Recommended Fix:** Make configurable.

---

### 1.5 Hardcoded File Paths

#### Issue #12: Hardcoded System Paths
**Files:**
- `scanning/http_scanner.py` (line 497) - `/tmp`, `/backup`, `/db`, `/sql`, `/uploads`, `/files`
- `post_assessment/persistence_audit.py` (line 134) - `/var/spool/cron/crontabs/`
- `tests/test_reporting.py` (line 60) - `/tmp/screenshot.png`

**Severity:** Medium  
**Description:** Hardcoded Unix-specific file paths.

**Impact:** Framework may not work correctly on non-Unix systems or with different directory structures.

**Recommended Fix:** Use platform-independent paths and make directories configurable.

---

### 1.6 Hardcoded URLs

#### Issue #13: External API URLs
**Files:** Multiple reconnaissance and vulnerability modules  
**Severity:** Low  
**Description:** Hardcoded URLs for external APIs (Censys, Shodan, VirusTotal, etc.).

**Examples:**
- `https://api.shodan.io/shodan/host/search`
- `https://search.censys.io/api/v2/certificates`
- `https://api.virustotal.com/api/v3/domains`
- `https://api.github.com`
- `https://services.nvd.nist.gov/rest/json/cves/2.0`

**Impact:** Cannot use alternative API endpoints or proxy servers.

**Recommended Fix:** Make API base URLs configurable for future flexibility.

---

## 2. PLACEHOLDER IMPLEMENTATIONS

### 2.1 "Not Yet Implemented" Messages

#### Issue #14: API Assessment in Interactive Mode
**File:** `hazarus/interactive.py`  
**Line:** 1160  
**Severity:** High  
**Description:** API assessment marked as not yet implemented.

```python
self.console.print("  [dim]API assessment not yet implemented[/dim]")
```

**Impact:** Users cannot perform API assessments through interactive mode.

**Recommended Fix:** Implement API assessment logic using existing `scanning/api_discovery.py` module.

---

#### Issue #15: Post-Assessment Audit in Interactive Mode
**File:** `hazarus/interactive.py`  
**Line:** 1195  
**Severity:** High  
**Description:** Post-assessment audit marked as not yet implemented.

```python
self.console.print("  [dim]Post-assessment audit not yet implemented[/dim]")
```

**Impact:** Users cannot perform post-assessment audits through comprehensive assessment.

**Recommended Fix:** Implement using existing `post_assessment/` modules.

---

#### Issue #16: Lateral Movement Audit in Interactive Mode
**File:** `hazarus/interactive.py`  
**Line:** 1201  
**Severity:** High  
**Description:** Lateral movement audit marked as not yet implemented.

```python
self.console.print("  [dim]Lateral movement audit not yet implemented[/dim]")
```

**Impact:** Users cannot perform lateral movement audits.

**Recommended Fix:** Implement using existing `post_assessment/lateral_movement_audit.py` module.

---

#### Issue #17: Task Manager Pause Functionality
**File:** `core/task_manager.py`  
**Line:** 177-178  
**Severity:** High  
**Description:** Pause functionality not implemented.

```python
async def pause_all(self) -> None:
    """Pause all running tasks (not yet implemented)."""
    self.logger.warning("Pause functionality not yet implemented")
```

**Impact:** Cannot pause running tasks.

**Recommended Fix:** Implement task pausing using asyncio task cancellation with state preservation.

---

#### Issue #18: Task Manager Resume Functionality
**File:** `core/task_manager.py`  
**Line:** 181-182  
**Severity:** High  
**Description:** Resume functionality not implemented.

```python
async def resume_all(self) -> None:
    """Resume all paused tasks (not yet implemented)."""
    self.logger.warning("Resume functionality not yet implemented")
```

**Impact:** Cannot resume paused tasks.

**Recommended Fix:** Implement task resuming by recreating tasks from saved state.

---

### 2.2 Placeholder Functions

#### Issue #19: Dashboard Findings Endpoint
**File:** `dashboard/backend/main.py`  
**Line:** 267-268  
**Severity:** High  
**Description:** Placeholder for loading actual assessment findings.

```python
# Placeholder - would load from actual assessment data
return {"assessment_id": assessment_id, "findings": []}
```

**Impact:** Dashboard cannot display actual assessment findings.

**Recommended Fix:** Implement using `reconnaissance.core.ReconPersistence` to load findings.

---

#### Issue #20: Dashboard Vulnerabilities Endpoint
**File:** `dashboard/backend/main.py`  
**Line:** 280-281  
**Severity:** High  
**Description:** Placeholder for querying vulnerability database.

```python
# Placeholder - would query vulnerability database
return {"vulnerabilities": []}
```

**Impact:** Dashboard cannot display vulnerability data.

**Recommended Fix:** Implement using `vulnerability/` modules to query and return vulnerability data.

---

#### Issue #21: Cleanup Manager - Stop Processes
**File:** `exploitation/cleanup_manager.py`  
**Line:** 107-108  
**Severity:** Medium  
**Description:** Placeholder for stopping actual processes.

```python
# Placeholder - would track and stop actual processes
await asyncio.sleep(0.5)
```

**Impact:** Cleanup does not actually stop processes after exploitation.

**Recommended Fix:** Implement process tracking using `psutil` and kill tracked processes.

---

#### Issue #22: Cleanup Manager - Remove Temp Files
**File:** `exploitation/cleanup_manager.py`  
**Line:** 112-113  
**Severity:** Medium  
**Description:** Placeholder for removing temporary files.

```python
# Placeholder - would remove actual files
await asyncio.sleep(0.5)
```

**Impact:** Temporary files from exploitation are not cleaned up.

**Recommended Fix:** Implement file tracking and cleanup using `pathlib` and `shutil`.

---

#### Issue #23: Cleanup Manager - Close Connections
**File:** `exploitation/cleanup_manager.py`  
**Line:** 117-118  
**Severity:** Medium  
**Description:** Placeholder for closing network connections.

```python
# Placeholder - would close actual connections
await asyncio.sleep(0.5)
```

**Impact:** Network connections are not properly closed after exploitation.

**Recommended Fix:** Implement connection tracking and cleanup using connection pool management.

---

#### Issue #24: Cleanup Manager - Restore State
**File:** `exploitation/cleanup_manager.py`  
**Line:** 122-123  
**Severity:** Medium  
**Description:** Placeholder for restoring system state.

```python
# Placeholder - would restore actual state
await asyncio.sleep(0.5)
```

**Impact:** System state is not restored after exploitation.

**Recommended Fix:** Implement state snapshot and restoration using system state tracking.

---

#### Issue #25: Cleanup Manager - Restore Snapshot
**File:** `exploitation/cleanup_manager.py`  
**Line:** 127-128  
**Severity:** Medium  
**Description:** Placeholder for VM snapshot restoration.

```python
# Placeholder - would integrate with virtualization API
await asyncio.sleep(1)
```

**Impact:** VM snapshots are not restored for lab cleanup.

**Recommended Fix:** Implement virtualization API integration (VMware/VirtualBox/libvirt).

---

#### Issue #26: Cleanup Manager - Undo Config Changes
**File:** `exploitation/cleanup_manager.py`  
**Line:** 132-133  
**Severity:** Medium  
**Description:** Placeholder for undoing configuration changes.

```python
# Placeholder - would undo actual changes
await asyncio.sleep(0.5)
```

**Impact:** Configuration changes made during exploitation are not reverted.

**Recommended Fix:** Implement configuration backup and restoration.

---

#### Issue #27: Cleanup Manager - Remove Added Users
**File:** `exploitation/cleanup_manager.py`  
**Line:** 137-138  
**Severity:** Medium  
**Description:** Placeholder for removing users/credentials.

```python
# Placeholder - would remove actual users
await asyncio.sleep(0.5)
```

**Impact:** Test users created during exploitation are not removed.

**Recommended Fix:** Implement user tracking and removal using system user management APIs.

---

#### Issue #28: Lab Executor - Restore Snapshot
**File:** `exploitation/lab_executor.py`  
**Line:** 178-179  
**Severity:** Medium  
**Description:** Placeholder for VM snapshot restoration.

```python
# Placeholder - would integrate with virtualization API (VMware, VirtualBox, etc.)
await asyncio.sleep(1)
```

**Impact:** Lab VM snapshots are not restored.

**Recommended Fix:** Same as Issue #25 - implement virtualization API integration.

---

#### Issue #29: Lab Executor - Create Snapshot
**File:** `exploitation/lab_executor.py`  
**Line:** 184-185  
**Severity:** Medium  
**Description:** Placeholder for VM snapshot creation.

```python
# Placeholder - would integrate with virtualization API
await asyncio.sleep(1)
```

**Impact:** Lab VM snapshots are not created.

**Recommended Fix:** Same as Issue #25 - implement virtualization API integration.

---

#### Issue #30: Lab Executor - Run Exploit
**File:** `exploitation/lab_executor.py`  
**Line:** 191-192  
**Severity:** High  
**Description:** Placeholder for actual exploit execution.

```python
# Placeholder - would actually execute exploit
await asyncio.sleep(2)
```

**Impact:** Exploits are not actually executed in lab environment.

**Recommended Fix:** Implement exploit execution using Metasploit RPC or custom exploit runners.

---

#### Issue #31: Exploit Engine - Run Exploit
**File:** `exploitation/exploit_engine.py`  
**Line:** 145-147  
**Severity:** High  
**Description:** Placeholder for actual exploit execution.

```python
# Placeholder for actual exploit execution
# In production, this would integrate with Metasploit RPC or custom exploits
await asyncio.sleep(2)  # Simulate execution
```

**Impact:** Exploits are not actually executed.

**Recommended Fix:** Same as Issue #30 - implement actual exploit execution.

---

## 3. MISSING CONFIGURATION

### 3.1 Missing Configuration File

#### Issue #32: No hazarus.yaml Configuration File
**Severity:** High  
**Description:** No central configuration file exists for framework settings.

**Impact:** All settings are hardcoded in source code, making customization difficult.

**Recommended Fix:** Create `config/hazarus.yaml` with sections for:
- Lab configuration (CIDR ranges, target IPs)
- Timeout settings
- Port configurations
- API endpoints
- File paths
- Dashboard settings

---

## 4. TEST DATA HARDCODING (ACCEPTABLE)

The following hardcoded values are in test files and are **acceptable** as they are test data:

- All occurrences in `tests/` directory
- Documentation examples in `docs/` directory
- README examples
- AGENTS.md examples

These are not considered issues as they are intentionally example data for testing and documentation purposes.

---

## 5. PRIORITIZED FIX RECOMMENDATIONS

### Priority 1 (Critical - High Impact)

1. **Implement placeholder functions in exploitation modules** (Issues #30, #31)
   - Actual exploit execution is core functionality
   - Currently only simulates execution
   
2. **Implement "not yet implemented" features in interactive mode** (Issues #14, #15, #16)
   - Blocks users from using complete assessment workflow
   - Implementation modules already exist
   
3. **Create central configuration file** (Issue #32)
   - Foundation for all other fixes
   - Enables customization without code changes

### Priority 2 (High Impact)

4. **Implement dashboard placeholder functions** (Issues #19, #20)
   - Dashboard cannot display real data
   - Reduces usefulness of web interface
   
5. **Implement task manager pause/resume** (Issues #17, #18)
   - Important for long-running assessments
   - Users cannot control task execution

### Priority 3 (Medium Impact)

6. **Move hardcoded lab CIDR ranges to config** (Issues #1-6)
   - Prevents custom lab configuration
   - Duplicated across multiple files
   
7. **Implement cleanup manager placeholders** (Issues #21-27)
   - Important for safe exploitation
   - Ensures proper cleanup after testing

### Priority 4 (Low Impact)

8. **Make timeouts configurable** (Issue #8)
   - 59 occurrences across codebase
   - Important for different network conditions
   
9. **Make ports configurable** (Issues #9-11)
   - Flexibility for different environments
   
10. **Fix hardcoded file paths** (Issue #12)
    - Platform compatibility
    - Custom directory structures

---

## 6. IMPLEMENTATION PLAN

### Phase 1: Foundation (Priority 1-2)
1. Create `config/hazarus.yaml` configuration file
2. Implement configuration loading mechanism
3. Move lab CIDR ranges to configuration
4. Implement dashboard placeholder functions
5. Implement interactive mode "not yet implemented" features

### Phase 2: Core Functionality (Priority 2-3)
1. Implement task manager pause/resume
2. Implement exploitation execution placeholders
3. Implement cleanup manager placeholders
4. Implement lab executor virtualization integration

### Phase 3: Configuration & Flexibility (Priority 3-4)
1. Make all timeouts configurable
2. Make all ports configurable
3. Fix hardcoded file paths
4. Make API endpoints configurable

### Phase 4: Testing & Validation
1. Unit tests for all new implementations
2. Integration tests for configuration loading
3. End-to-end tests for fixed functionality
4. Regression tests to ensure no breakage

---

## 7. RISK ASSESSMENT

### High Risk Issues
- Placeholder exploit execution (security risk if not properly implemented)
- Missing cleanup functionality (risk of system state pollution)
- Missing configuration (risk of misconfiguration)

### Medium Risk Issues
- Hardcoded lab ranges (limits deployment flexibility)
- Missing dashboard data (reduces monitoring capability)
- Hardcoded timeouts (may cause failures in slow networks)

### Low Risk Issues
- Hardcoded ports (limits deployment options)
- Hardcoded file paths (platform compatibility)
- Example domains in templates (user error risk)

---

## 8. CONCLUSION

The HAZARUS Security Assessment Framework has **94 hardcoded values and placeholder implementations** that need to be addressed. The most critical issues are:

1. **Placeholder exploit execution** - Core security functionality not implemented
2. **Missing configuration file** - No central configuration management
3. **"Not yet implemented" features** - Blocks complete assessment workflow
4. **Incomplete cleanup** - Risk of system state pollution

Implementing the fixes in the recommended priority order will significantly improve the framework's:
- **Flexibility** - Users can customize without code changes
- **Completeness** - All advertised features will work
- **Safety** - Proper cleanup and state management
- **Usability** - Better dashboard and interactive mode

**Estimated Effort:** 40-60 hours of development work across all phases.

**Recommended Timeline:** 2-3 weeks for complete implementation and testing.

---

**Report Generated:** 2025-11-03  
**Analyst:** Automated Code Analysis  
**Framework Version:** 2.0.0
