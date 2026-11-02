"""
HAZARUS Dependency Audit
Dependency vulnerability analysis.
"""

import asyncio
import logging
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class Dependency:
    """A dependency."""
    name: str
    version: str
    ecosystem: str
    vulnerabilities: List[str] = field(default_factory=list)
    outdated: bool = False
    latest_version: Optional[str] = None


@dataclass
class DependencyAuditResult:
    """Dependency audit result."""
    path: str
    dependencies: List[Dependency] = field(default_factory=list)
    ecosystem: str = "unknown"
    vulnerable_count: int = 0
    outdated_count: int = 0
    audited_at: datetime = None

    def __post_init__(self):
        if self.audited_at is None:
            self.audited_at = datetime.utcnow()


class DependencyAudit:
    """Dependency audit module."""

    def __init__(self):
        self.logger = logging.getLogger("hazarus.dependency_audit")

    async def audit(self, path: str) -> DependencyAuditResult:
        """Audit dependencies for vulnerabilities."""
        self.logger.info(f"Auditing dependencies in {path}")

        result = DependencyAuditResult(path=path)

        # Detect ecosystem
        result.ecosystem = self._detect_ecosystem(path)

        try:
            # Parse dependency file
            if result.ecosystem == "python":
                await self._audit_python(path, result)
            elif result.ecosystem == "node":
                await self._audit_node(path, result)
            elif result.ecosystem == "ruby":
                await self._audit_ruby(path, result)
            else:
                self.logger.warning(f"Unsupported ecosystem: {result.ecosystem}")

            # Count vulnerabilities
            result.vulnerable_count = sum(len(d.vulnerabilities) for d in result.dependencies)
            result.outdated_count = sum(1 for d in result.dependencies if d.outdated)

            self.logger.info(f"Dependency audit complete: {len(result.dependencies)} dependencies")

        except Exception as e:
            self.logger.error(f"Dependency audit failed: {e}")

        return result

    def _detect_ecosystem(self, path: str) -> str:
        """Detect the package ecosystem."""
        path_obj = Path(path)

        if (path_obj / "requirements.txt").exists() or (path_obj / "pyproject.toml").exists():
            return "python"
        elif (path_obj / "package.json").exists():
            return "node"
        elif (path_obj / "Gemfile").exists():
            return "ruby"

        return "unknown"

    async def _audit_python(self, path: str, result: DependencyAuditResult) -> None:
        """Audit Python dependencies."""
        path_obj = Path(path)

        # Try requirements.txt
        req_file = path_obj / "requirements.txt"
        if req_file.exists():
            with open(req_file, "r") as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    # Parse requirement
                    parts = line.split("==")
                    name = parts[0].strip()
                    version = parts[1].strip() if len(parts) > 1 else "unknown"

                    dep = Dependency(
                        name=name,
                        version=version,
                        ecosystem="python"
                    )

                    # Check for known vulnerabilities (simplified)
                    await self._check_vulnerabilities(dep)

                    result.dependencies.append(dep)

    async def _audit_node(self, path: str, result: DependencyAuditResult) -> None:
        """Audit Node.js dependencies."""
        path_obj = Path(path)
        package_file = path_obj / "package.json"

        if package_file.exists():
            with open(package_file, "r") as f:
                data = json.load(f)

            dependencies = data.get("dependencies", {})
            dev_dependencies = data.get("devDependencies", {})

            all_deps = {**dependencies, **dev_dependencies}

            for name, version in all_deps.items():
                dep = Dependency(
                    name=name,
                    version=version,
                    ecosystem="node"
                )

                await self._check_vulnerabilities(dep)
                result.dependencies.append(dep)

    async def _audit_ruby(self, path: str, result: DependencyAuditResult) -> None:
        """Audit Ruby dependencies."""
        path_obj = Path(path)
        gemfile = path_obj / "Gemfile"

        if gemfile.exists():
            with open(gemfile, "r") as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()
                if line.startswith("gem "):
                    # Parse gem
                    parts = line.split()
                    name = parts[1].strip('"\'')
                    version = parts[2].strip('"\'') if len(parts) > 2 else "unknown"

                    dep = Dependency(
                        name=name,
                        version=version,
                        ecosystem="ruby"
                    )

                    await self._check_vulnerabilities(dep)
                    result.dependencies.append(dep)

    async def _check_vulnerabilities(self, dep: Dependency) -> None:
        """Check dependency for known vulnerabilities."""
        # Simplified - in production would use OSV, Snyk, or similar APIs
        # For now, just flag some known vulnerable versions as examples
        known_vulns = {
            "python": {
                "django": ["1.11.0", "2.0.0"],
                "flask": ["0.12.0"],
                "requests": ["2.20.0"]
            },
            "node": {
                "express": ["4.16.0"],
                "lodash": ["4.17.0"]
            }
        }

        ecosystem_vulns = known_vulns.get(dep.ecosystem, {})
        if dep.name.lower() in ecosystem_vulns:
            if dep.version in ecosystem_vulns[dep.name.lower()]:
                dep.vulnerabilities.append(f"Known vulnerable version: {dep.version}")

    def to_dict(self, result: DependencyAuditResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "path": result.path,
            "ecosystem": result.ecosystem,
            "dependencies": [
                {
                    "name": d.name,
                    "version": d.version,
                    "ecosystem": d.ecosystem,
                    "vulnerabilities": d.vulnerabilities,
                    "outdated": d.outdated,
                    "latest_version": d.latest_version
                }
                for d in result.dependencies
            ],
            "vulnerable_count": result.vulnerable_count,
            "outdated_count": result.outdated_count,
            "audited_at": result.audited_at.isoformat()
        }
