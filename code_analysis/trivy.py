"""
HAZARUS Trivy Scanner
Trivy integration for vulnerability scanning.
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
class Vulnerability:
    """Vulnerability from Trivy."""
    vulnerability_id: str
    package_name: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    title: str
    description: str


@dataclass
class TrivyResult:
    """Trivy scan result."""
    target: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    severity_summary: Dict[str, int] = field(default_factory=dict)
    scan_duration: Optional[float] = None
    scanned_at: datetime = None

    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class TrivyScanner:
    """Trivy scanning module."""

    def __init__(self, trivy_path: str = "trivy"):
        self.trivy_path = trivy_path
        self.logger = logging.getLogger("hazarus.trivy_scanner")

    async def scan(self, path: str, scan_type: str = "fs") -> TrivyResult:
        """Scan with Trivy."""
        self.logger.info(f"Scanning {path} with Trivy (type: {scan_type})")

        result = TrivyResult(target=path)

        # Build trivy command
        command = self._build_command(path, scan_type)

        try:
            start_time = datetime.utcnow()

            # Execute trivy
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=600
            )

            end_time = datetime.utcnow()
            result.scan_duration = (end_time - start_time).total_seconds()

            # Parse JSON output
            if process.returncode == 0:
                data = json.loads(stdout.decode())

                for result_data in data.get("Results", []):
                    for vuln_data in result_data.get("Vulnerabilities", []):
                        vuln = Vulnerability(
                            vulnerability_id=vuln_data.get("VulnerabilityID", ""),
                            package_name=vuln_data.get("PkgName", ""),
                            installed_version=vuln_data.get("InstalledVersion", ""),
                            fixed_version=vuln_data.get("FixedVersion"),
                            severity=vuln_data.get("Severity", "unknown"),
                            title=vuln_data.get("Title", ""),
                            description=vuln_data.get("Description", "")
                        )
                        result.vulnerabilities.append(vuln)

                # Generate severity summary
                result.severity_summary = self._generate_severity_summary(result.vulnerabilities)

                self.logger.info(f"Trivy scan complete: {len(result.vulnerabilities)} vulnerabilities")
            else:
                self.logger.error(f"Trivy failed with status {process.returncode}")

        except asyncio.TimeoutError:
            self.logger.error("Trivy scan timed out")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Trivy output: {e}")
        except Exception as e:
            self.logger.error(f"Trivy scan failed: {e}")

        return result

    def _build_command(self, path: str, scan_type: str) -> List[str]:
        """Build trivy command."""
        command = [
            self.trivy_path,
            scan_type,
            "--format", "json",
            "--no-progress",
            "--exit-code", "0",  # Don't fail on vulnerabilities
            path
        ]

        return command

    def _generate_severity_summary(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Generate severity summary."""
        summary = {}

        for vuln in vulnerabilities:
            sev = vuln.severity.lower()
            summary[sev] = summary.get(sev, 0) + 1

        return summary

    async def check_installed(self) -> bool:
        """Check if Trivy is installed."""
        try:
            process = await asyncio.create_subprocess_exec(
                self.trivy_path, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            return process.returncode == 0
        except Exception:
            return False

    def to_dict(self, result: TrivyResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": result.target,
            "vulnerabilities": [
                {
                    "vulnerability_id": v.vulnerability_id,
                    "package_name": v.package_name,
                    "installed_version": v.installed_version,
                    "fixed_version": v.fixed_version,
                    "severity": v.severity,
                    "title": v.title,
                    "description": v.description
                }
                for v in result.vulnerabilities
            ],
            "severity_summary": result.severity_summary,
            "scan_duration": result.scan_duration,
            "scanned_at": result.scanned_at.isoformat()
        }
