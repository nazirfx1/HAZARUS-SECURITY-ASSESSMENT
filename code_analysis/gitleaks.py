"""
HAZARUS Gitleaks Scanner
Gitleaks integration for secret detection.
"""

import asyncio
import logging
import subprocess
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class SecretFinding:
    """Secret finding."""
    rule_id: str
    description: str
    file: str
    line: int
    secret: str
    severity: str


@dataclass
class GitleaksResult:
    """Gitleaks scan result."""
    path: str
    findings: List[SecretFinding] = field(default_factory=list)
    severity_summary: Dict[str, int] = field(default_factory=dict)
    scan_duration: Optional[float] = None
    scanned_at: datetime = None

    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class GitleaksScanner:
    """Gitleaks scanning module."""

    def __init__(self, gitleaks_path: str = "gitleaks"):
        self.gitleaks_path = gitleaks_path
        self.logger = logging.getLogger("hazarus.gitleaks_scanner")

    async def scan(self, path: str) -> GitleaksResult:
        """Scan for secrets with Gitleaks."""
        self.logger.info(f"Scanning {path} with Gitleaks")

        result = GitleaksResult(path=path)

        # Build gitleaks command
        command = self._build_command(path)

        try:
            start_time = datetime.utcnow()

            # Execute gitleaks
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300
            )

            end_time = datetime.utcnow()
            result.scan_duration = (end_time - start_time).total_seconds()

            # Parse JSON output
            if process.returncode == 0:
                data = json.loads(stdout.decode())

                for finding_data in data:
                    finding = SecretFinding(
                        rule_id=finding_data.get("RuleID", ""),
                        description=finding_data.get("Description", ""),
                        file=finding_data.get("File", ""),
                        line=finding_data.get("LineNumber", 0),
                        secret=finding_data.get("Secret", ""),
                        severity=finding_data.get("Severity", "medium")
                    )
                    result.findings.append(finding)

                # Generate severity summary
                result.severity_summary = self._generate_severity_summary(result.findings)

                self.logger.info(f"Gitleaks scan complete: {len(result.findings)} secrets found")
            else:
                self.logger.error(f"Gitleaks failed with status {process.returncode}")

        except asyncio.TimeoutError:
            self.logger.error("Gitleaks scan timed out")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Gitleaks output: {e}")
        except Exception as e:
            self.logger.error(f"Gitleaks scan failed: {e}")

        return result

    def _build_command(self, path: str) -> List[str]:
        """Build gitleaks command."""
        command = [
            self.gitleaks_path,
            "detect",
            "--source", path,
            "--report-format", "json",
            "--report-path", "-",  # stdout
            "--no-git"
        ]

        return command

    def _generate_severity_summary(self, findings: List[SecretFinding]) -> Dict[str, int]:
        """Generate severity summary."""
        summary = {}

        for finding in findings:
            sev = finding.severity.lower()
            summary[sev] = summary.get(sev, 0) + 1

        return summary

    async def check_installed(self) -> bool:
        """Check if Gitleaks is installed."""
        try:
            process = await asyncio.create_subprocess_exec(
                self.gitleaks_path, "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            return process.returncode == 0
        except Exception:
            return False

    def to_dict(self, result: GitleaksResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "path": result.path,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "description": f.description,
                    "file": f.file,
                    "line": f.line,
                    "secret": f.secret[:20] + "..." if f.secret else "",  # Truncate for security
                    "severity": f.severity
                }
                for f in result.findings
            ],
            "severity_summary": result.severity_summary,
            "scan_duration": result.scan_duration,
            "scanned_at": result.scanned_at.isoformat()
        }
