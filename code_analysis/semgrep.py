"""
HAZARUS Semgrep Analyzer
Semgrep integration for static analysis.
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
class SemgrepFinding:
    """Semgrep finding."""
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    column: int
    code: str


@dataclass
class SemgrepResult:
    """Semgrep analysis result."""
    path: str
    findings: List[SemgrepFinding] = field(default_factory=list)
    severity_summary: Dict[str, int] = field(default_factory=dict)
    scan_duration: Optional[float] = None
    analyzed_at: datetime = None

    def __post_init__(self):
        if self.analyzed_at is None:
            self.analyzed_at = datetime.utcnow()


class SemgrepAnalyzer:
    """Semgrep analysis module."""

    def __init__(self, semgrep_path: str = "semgrep"):
        self.semgrep_path = semgrep_path
        self.logger = logging.getLogger("hazarus.semgrep_analyzer")

    async def analyze(self, path: str, rules: Optional[str] = None) -> SemgrepResult:
        """Analyze code with Semgrep."""
        self.logger.info(f"Analyzing {path} with Semgrep")

        result = SemgrepResult(path=path)

        # Build semgrep command
        command = self._build_command(path, rules)

        try:
            start_time = datetime.utcnow()

            # Execute semgrep
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

                for finding_data in data.get("results", []):
                    finding = SemgrepFinding(
                        rule_id=finding_data.get("check_id", ""),
                        severity=finding_data.get("extra", {}).get("severity", "unknown"),
                        message=finding_data.get("message", ""),
                        file=finding_data.get("path", ""),
                        line=finding_data.get("start", {}).get("line", 0),
                        column=finding_data.get("start", {}).get("col", 0),
                        code=finding_data.get("extra", {}).get("lines", "")
                    )
                    result.findings.append(finding)

                # Generate severity summary
                result.severity_summary = self._generate_severity_summary(result.findings)

                self.logger.info(f"Semgrep analysis complete: {len(result.findings)} findings")
            else:
                self.logger.error(f"Semgrep failed with status {process.returncode}")

        except asyncio.TimeoutError:
            self.logger.error("Semgrep analysis timed out")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Semgrep output: {e}")
        except Exception as e:
            self.logger.error(f"Semgrep analysis failed: {e}")

        return result

    def _build_command(self, path: str, rules: Optional[str]) -> List[str]:
        """Build semgrep command."""
        command = [
            self.semgrep_path,
            "--config", "auto",
            "--json",
            "--no-git-ignore",
            path
        ]

        if rules:
            command.extend(["--config", rules])

        return command

    def _generate_severity_summary(self, findings: List[SemgrepFinding]) -> Dict[str, int]:
        """Generate severity summary."""
        summary = {}

        for finding in findings:
            sev = finding.severity.lower()
            summary[sev] = summary.get(sev, 0) + 1

        return summary

    async def check_installed(self) -> bool:
        """Check if Semgrep is installed."""
        try:
            process = await asyncio.create_subprocess_exec(
                self.semgrep_path, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            return process.returncode == 0
        except Exception:
            return False

    def to_dict(self, result: SemgrepResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "path": result.path,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "message": f.message,
                    "file": f.file,
                    "line": f.line,
                    "column": f.column,
                    "code": f.code
                }
                for f in result.findings
            ],
            "severity_summary": result.severity_summary,
            "scan_duration": result.scan_duration,
            "analyzed_at": result.analyzed_at.isoformat()
        }
