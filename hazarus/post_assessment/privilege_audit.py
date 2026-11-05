"""
HAZARUS Privilege Audit
Privilege escalation and configuration audit.
"""

import asyncio
import logging
import subprocess
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PrivilegeFinding:
    """Privilege escalation finding."""
    type: str
    description: str
    severity: str
    evidence: str
    location: Optional[str] = None


@dataclass
class PrivilegeAuditResult:
    """Privilege audit result."""
    target: str
    findings: List[PrivilegeFinding] = field(default_factory=list)
    sudo_rules: List[str] = field(default_factory=list)
    suid_files: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    high_risk_count: int = 0
    audited_at: datetime = None

    def __post_init__(self):
        if self.audited_at is None:
            self.audited_at = datetime.utcnow()


class PrivilegeAudit:
    """Privilege audit module."""

    def __init__(self):
        self.logger = logging.getLogger("hazarus.privilege_audit")

    async def audit(self, target: str) -> PrivilegeAuditResult:
        """Audit privilege configuration on target."""
        self.logger.info(f"Auditing privileges on {target}")

        result = PrivilegeAuditResult(target=target)

        try:
            # Check SUID files
            await self._check_suid_files(result)

            # Check sudo configuration
            await self._check_sudo_config(result)

            # Check capabilities
            await self._check_capabilities(result)

            # Check writable paths
            await self._check_writable_paths(result)

            # Count high-risk findings
            result.high_risk_count = len([f for f in result.findings if f.severity == "high"])

            self.logger.info(f"Privilege audit complete: {len(result.findings)} findings")

        except Exception as e:
            self.logger.error(f"Privilege audit failed: {e}")
            result.findings.append(PrivilegeFinding(
                type="error",
                description=f"Audit failed: {str(e)}",
                severity="critical",
                evidence=str(e)
            ))

        return result

    async def _check_suid_files(self, result: PrivilegeAuditResult) -> None:
        """Check for SUID/SGID files."""
        try:
            # Check if we're auditing a local system or remote target
            # For remote targets, we can't check SUID files directly
            if "/" not in result.target or not result.target.startswith("/"):
                self.logger.info("Target is not a local path, skipping SUID file check")
                result.findings.append(PrivilegeFinding(
                    type="info",
                    description="SUID file check skipped - target is not a local filesystem",
                    severity="info",
                    evidence="Remote target"
                ))
                return

            process = await asyncio.create_subprocess_exec(
                "find", result.target, "-perm", "-4000", "-o", "-perm", "-2000",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                files = stdout.decode().strip().split("\n")
                result.suid_files = [f for f in files if f]

                # Flag risky SUID files
                risky_files = [
                    "/bin/passwd", "/bin/su", "/usr/bin/sudo",
                    "/usr/bin/passwd", "/usr/bin/su"
                ]
                
                for file in result.suid_files:
                    if any(risk in file for risk in risky_files):
                        result.findings.append(PrivilegeFinding(
                            type="suid",
                            description=f"Risky SUID file: {file}",
                            severity="high",
                            evidence=file,
                            location=file
                        ))
                else:
                    self.logger.info(f"Found {len(result.suid_files)} SUID/SGID files")

        except Exception as e:
            self.logger.warning(f"SUID file check failed: {e}")

    async def _check_sudo_config(self, result: PrivilegeAuditResult) -> None:
        """Check sudo configuration."""
        try:
            process = await asyncio.create_subprocess_exec(
                "sudo", "-l",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                sudo_rules = stdout.decode().strip().split("\n")
                result.sudo_rules = [r for r in sudo_rules if r]

                # Check for dangerous sudo rules
                for rule in result.sudo_rules:
                    if "ALL" in rule and "NOPASSWD" in rule:
                        result.findings.append(PrivilegeFinding(
                            type="sudo",
                            description="Passwordless sudo with ALL privileges",
                            severity="high",
                            evidence=rule
                        ))

        except Exception as e:
            self.logger.error(f"Sudo check failed: {e}")

    async def _check_capabilities(self, result: PrivilegeAuditResult) -> None:
        """Check Linux capabilities."""
        try:
            process = await asyncio.create_subprocess_exec(
                "getcap", "-r", "/",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                caps = stdout.decode().strip().split("\n")
                result.capabilities = [c for c in caps if c]

                # Flag dangerous capabilities
                dangerous_caps = ["cap_setuid", "cap_setgid", "cap_sys_admin"]

                for cap in result.capabilities:
                    for dangerous in dangerous_caps:
                        if dangerous in cap:
                            result.findings.append(PrivilegeFinding(
                                type="capability",
                                description=f"Dangerous capability: {cap}",
                                severity="high",
                                evidence=cap
                            ))

        except Exception as e:
            self.logger.error(f"Capabilities check failed: {e}")

    async def _check_writable_paths(self, result: PrivilegeAuditResult) -> None:
        """Check for world-writable paths."""
        try:
            process = await asyncio.create_subprocess_exec(
                "find", "/", "-perm", "-o+w", "-type", "d",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                paths = stdout.decode().strip().split("\n")
                writable_paths = [p for p in paths if p and not p.startswith("/proc") and not p.startswith("/sys")]

                for path in writable_paths[:20]:  # Limit to 20
                    result.findings.append(PrivilegeFinding(
                        type="writable",
                        description=f"World-writable directory: {path}",
                        severity="medium",
                        evidence=path
                    ))

        except Exception as e:
            self.logger.error(f"Writable paths check failed: {e}")

    def to_dict(self, result: PrivilegeAuditResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": result.target,
            "findings": [
                {
                    "type": f.type,
                    "description": f.description,
                    "severity": f.severity,
                    "evidence": f.evidence,
                    "location": f.location
                }
                for f in result.findings
            ],
            "sudo_rules": result.sudo_rules,
            "suid_files": result.suid_files,
            "capabilities": result.capabilities,
            "high_risk_count": result.high_risk_count,
            "audited_at": result.audited_at.isoformat()
        }
