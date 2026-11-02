"""
HAZARUS Credential Exposure
Credential exposure detection and analysis.
"""

import asyncio
import logging
import subprocess
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, UTC
import re


@dataclass
class CredentialFinding:
    """Credential exposure finding."""
    type: str
    location: str
    description: str
    severity: str
    evidence: str


@dataclass
class CredentialExposureResult:
    """Credential exposure result."""
    target: str
    findings: List[CredentialFinding] = field(default_factory=list)
    ssh_keys: List[str] = field(default_factory=list)
    password_files: List[str] = field(default_factory=list)
    exposed_passwords: List[str] = field(default_factory=list)
    audited_at: datetime = None

    def __post_init__(self):
        if self.audited_at is None:
            self.audited_at = datetime.now(UTC)


class CredentialExposure:
    """Credential exposure module."""

    def __init__(self):
        self.logger = logging.getLogger("hazarus.credential_exposure")

    async def detect(self, target: str) -> CredentialExposureResult:
        """Detect credential exposure on target."""
        self.logger.info(f"Detecting credential exposure on {target}")

        result = CredentialExposureResult(target=target)

        try:
            # Check for SSH keys
            await self._check_ssh_keys(result)

            # Check for password files
            await self._check_password_files(result)

            # Check for exposed passwords in config files
            await self._check_config_files(result)

            # Check for cached credentials
            await self._check_cached_credentials(result)

            self.logger.info(f"Credential exposure check complete: {len(result.findings)} findings")

        except Exception as e:
            self.logger.error(f"Credential exposure check failed: {e}")

        return result

    async def _check_ssh_keys(self, result: CredentialExposureResult) -> None:
        """Check for exposed SSH keys."""
        ssh_paths = [
            "/root/.ssh/id_rsa",
            "/root/.ssh/id_dsa",
            "/home/*/.ssh/id_rsa",
            "/home/*/.ssh/id_dsa"
        ]

        for path in ssh_paths:
            try:
                process = await asyncio.create_subprocess_exec(
                    "ls", path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()

                if process.returncode == 0:
                    result.ssh_keys.append(path)
                    result.findings.append(CredentialFinding(
                        type="ssh_key",
                        location=path,
                        description="SSH private key found",
                        severity="high",
                        evidence=path
                    ))

            except Exception:
                pass

    async def _check_password_files(self, result: CredentialExposureResult) -> None:
        """Check for password files."""
        password_files = [
            "/etc/shadow",
            "/etc/passwd",
            "/root/.bash_history",
            "/home/*/.bash_history"
        ]

        for path in password_files:
            try:
                process = await asyncio.create_subprocess_exec(
                    "ls", path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()

                if process.returncode == 0:
                    result.password_files.append(path)
                    result.findings.append(CredentialFinding(
                        type="password_file",
                        location=path,
                        description="Password-related file found",
                        severity="medium",
                        evidence=path
                    ))

            except Exception:
                pass

    async def _check_config_files(self, result: CredentialExposureResult) -> None:
        """
        Check for exposed passwords in config files.
        Reports file paths and presence indicators only - never extracts actual passwords.
        """
        config_paths = [
            "/etc/*.conf",
            "/root/.config/*",
            "/home/*/.config/*"
        ]

        for path in config_paths:
            try:
                # Check if files exist that might contain credentials
                process = await asyncio.create_subprocess_exec(
                    "bash", "-c", f"ls {path} 2>/dev/null | head -5",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()

                if process.returncode == 0 and stdout.strip():
                    files = stdout.decode().strip().split("\n")
                    for file in files:
                        if file:
                            # Check if file contains password-related keywords (without showing values)
                            check_process = await asyncio.create_subprocess_exec(
                                "bash", "-c", f"grep -qi -E '(password|passwd|secret|key|token)' {path}/{file} 2>/dev/null && echo 'KEYWORDS_FOUND'",
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE
                            )
                            check_stdout, check_stderr = await check_process.communicate()

                            if b"KEYWORDS_FOUND" in check_stdout:
                                result.findings.append(CredentialFinding(
                                    type="config_password",
                                    location=f"{path}/{file}",
                                    description="Config file contains credential-related keywords",
                                    severity="medium",
                                    evidence="File path only - no values extracted"
                                ))

            except Exception:
                pass

    async def _check_cached_credentials(self, result: CredentialExposureResult) -> None:
        """Check for cached credentials."""
        try:
            process = await asyncio.create_subprocess_exec(
                "ls", "/root/.cache",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                result.findings.append(CredentialFinding(
                    type="cache",
                    location="/root/.cache",
                    description="Cache directory found - may contain credentials",
                    severity="low",
                    evidence="/root/.cache"
                ))

        except Exception:
            pass

    def to_dict(self, result: CredentialExposureResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": result.target,
            "findings": [
                {
                    "type": f.type,
                    "location": f.location,
                    "description": f.description,
                    "severity": f.severity,
                    "evidence": f.evidence
                }
                for f in result.findings
            ],
            "ssh_keys": result.ssh_keys,
            "password_files": result.password_files,
            "exposed_passwords": result.exposed_passwords,
            "audited_at": result.audited_at.isoformat()
        }
