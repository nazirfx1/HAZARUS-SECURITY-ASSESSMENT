"""
HAZARUS Secret Analysis
Secret and credential analysis.
"""

import asyncio
import logging
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class SecretFinding:
    """Secret finding."""
    type: str
    location: str
    line: int
    description: str
    severity: str
    secret_preview: str


@dataclass
class SecretAnalysisResult:
    """Secret analysis result."""
    path: str
    findings: List[SecretFinding] = field(default_factory=list)
    types_found: List[str] = field(default_factory=list)
    analyzed_at: datetime = None

    def __post_init__(self):
        if self.analyzed_at is None:
            self.analyzed_at = datetime.utcnow()


class SecretAnalysis:
    """Secret analysis module."""

    def __init__(self):
        self.logger = logging.getLogger("hazarus.secret_analysis")

        # Secret patterns
        self.patterns = {
            "api_key": r'(?:api[_-]?key|apikey)["\':\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            "aws_key": r'AKIA[0-9A-Z]{16}',
            "aws_secret": r'[0-9a-zA-Z/+]{40}',
            "github_token": r'ghp_[a-zA-Z0-9]{36}',
            "jwt": r'eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+',
            "private_key": r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
            "password": r'password["\':\s*["\']([^"\']{8,})["\']',
            "database_url": r'(?:mongodb|postgresql|mysql)://[^\s"\']+',
            "slack_token": r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32}',
        }

    async def analyze(self, path: str) -> SecretAnalysisResult:
        """Analyze for secrets in code."""
        self.logger.info(f"Analyzing {path} for secrets")

        result = SecretAnalysisResult(path=path)

        try:
            path_obj = Path(path)

            if path_obj.is_file():
                await self._analyze_file(path_obj, result)
            elif path_obj.is_dir():
                await self._analyze_directory(path_obj, result)

            # Collect types found
            result.types_found = list(set(f.type for f in result.findings))

            self.logger.info(f"Secret analysis complete: {len(result.findings)} secrets found")

        except Exception as e:
            self.logger.error(f"Secret analysis failed: {e}")

        return result

    async def _analyze_file(self, file_path: Path, result: SecretAnalysisResult) -> None:
        """Analyze a single file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            for secret_type, pattern in self.patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)

                for match in matches:
                    line_num = content[:match.start()].count("\n") + 1

                    # Get preview of the secret
                    secret_preview = match.group(0)
                    if len(secret_preview) > 50:
                        secret_preview = secret_preview[:50] + "..."

                    finding = SecretFinding(
                        type=secret_type,
                        location=str(file_path),
                        line=line_num,
                        description=f"Potential {secret_type} detected",
                        severity="high",
                        secret_preview=secret_preview
                    )

                    result.findings.append(finding)

        except Exception as e:
            self.logger.error(f"Failed to analyze file {file_path}: {e}")

    async def _analyze_directory(self, dir_path: Path, result: SecretAnalysisResult) -> None:
        """Analyze a directory recursively."""
        # Skip common non-code directories
        skip_dirs = {".git", "node_modules", "venv", "__pycache__", ".venv", "dist", "build"}

        for file_path in dir_path.rglob("*"):
            if file_path.is_file():
                # Skip if in skip directory
                if any(skip_dir in file_path.parts for skip_dir in skip_dirs):
                    continue

                # Only analyze certain file types
                if file_path.suffix in [".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".sh", ".yml", ".yaml", ".json", ".env", ".config"]:
                    await self._analyze_file(file_path, result)

    def to_dict(self, result: SecretAnalysisResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "path": result.path,
            "findings": [
                {
                    "type": f.type,
                    "location": f.location,
                    "line": f.line,
                    "description": f.description,
                    "severity": f.severity,
                    "secret_preview": f.secret_preview
                }
                for f in result.findings
            ],
            "types_found": result.types_found,
            "analyzed_at": result.analyzed_at.isoformat()
        }
