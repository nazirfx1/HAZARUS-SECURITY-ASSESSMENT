"""
HAZARUS Persistence Audit
Persistence mechanism detection and audit.
"""

import asyncio
import logging
import subprocess
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, UTC


@dataclass
class PersistenceMechanism:
    """Persistence mechanism finding."""
    type: str
    location: str
    description: str
    severity: str
    removable: bool


@dataclass
class PersistenceAuditResult:
    """Persistence audit result."""
    target: str
    mechanisms: List[PersistenceMechanism] = field(default_factory=list)
    systemd_services: List[str] = field(default_factory=list)
    cron_jobs: List[str] = field(default_factory=list)
    startup_files: List[str] = field(default_factory=list)
    audited_at: datetime = None

    def __post_init__(self):
        if self.audited_at is None:
            self.audited_at = datetime.now(UTC)


class PersistenceAudit:
    """Persistence audit module."""

    def __init__(self):
        self.logger = logging.getLogger("hazarus.persistence_audit")

    async def audit(self, target: str) -> PersistenceAuditResult:
        """Audit persistence mechanisms on target."""
        self.logger.info(f"Auditing persistence on {target}")

        result = PersistenceAuditResult(target=target)

        try:
            # Check systemd services
            await self._check_systemd_services(result)

            # Check cron jobs
            await self._check_cron_jobs(result)

            # Check startup files
            await self._check_startup_files(result)

            # Check profile files
            await self._check_profile_files(result)

            self.logger.info(f"Persistence audit complete: {len(result.mechanisms)} mechanisms")

        except Exception as e:
            self.logger.error(f"Persistence audit failed: {e}")

        return result

    async def _check_systemd_services(self, result: PersistenceAuditResult) -> None:
        """Check systemd services for persistence."""
        try:
            process = await asyncio.create_subprocess_exec(
                "systemctl", "list-units", "--type=service", "--all",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                services = stdout.decode().strip().split("\n")
                for service in services[1:]:  # Skip header
                    if service:
                        parts = service.split()
                        if len(parts) >= 4:
                            service_name = parts[0]
                            if "enabled" in parts:
                                result.systemd_services.append(service_name)

            # Check for suspicious user services
            try:
                process = await asyncio.create_subprocess_exec(
                    "systemctl", "--user", "list-units", "--type=service",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()

                if process.returncode == 0:
                    user_services = stdout.decode().strip().split("\n")
                    for service in user_services[1:]:
                        if service and "enabled" in service:
                            result.mechanisms.append(PersistenceMechanism(
                                type="systemd_user",
                                location=service.split()[0],
                                description="User systemd service enabled",
                                severity="medium",
                                removable=True
                            ))

            except Exception:
                pass

        except Exception as e:
            self.logger.error(f"Systemd check failed: {e}")

    async def _check_cron_jobs(self, result: PersistenceAuditResult) -> None:
        """Check cron jobs for persistence."""
        cron_paths = [
            "/etc/crontab",
            "/etc/cron.d/*",
            "/var/spool/cron/crontabs/*",
            "/root/.crontab",
            "/home/*/.crontab"
        ]

        for path in cron_paths:
            try:
                process = await asyncio.create_subprocess_exec(
                    "ls", path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()

                if process.returncode == 0:
                    result.cron_jobs.append(path)
                    result.mechanisms.append(PersistenceMechanism(
                        type="cron",
                        location=path,
                        description="Cron job found",
                        severity="medium",
                        removable=True
                    ))

            except Exception:
                pass

    async def _check_startup_files(self, result: PersistenceAuditResult) -> None:
        """Check startup files for persistence."""
        startup_files = [
            "/etc/rc.local",
            "/etc/init.d/*",
            "/root/.bashrc",
            "/root/.bash_profile",
            "/home/*/.bashrc",
            "/home/*/.bash_profile"
        ]

        for path in startup_files:
            try:
                process = await asyncio.create_subprocess_exec(
                    "ls", path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()

                if process.returncode == 0:
                    result.startup_files.append(path)

            except Exception:
                pass

    async def _check_profile_files(self, result: PersistenceAuditResult) -> None:
        """Check profile files for persistence."""
        profile_files = [
            "/etc/profile",
            "/etc/profile.d/*",
            "/root/.profile",
            "/home/*/.profile"
        ]

        for path in profile_files:
            try:
                process = await asyncio.create_subprocess_exec(
                    "ls", path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()

                if process.returncode == 0:
                    result.mechanisms.append(PersistenceMechanism(
                        type="profile",
                        location=path,
                        description="Profile file found",
                        severity="low",
                        removable=True
                    ))

            except Exception:
                pass

    def to_dict(self, result: PersistenceAuditResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": result.target,
            "mechanisms": [
                {
                    "type": m.type,
                    "location": m.location,
                    "description": m.description,
                    "severity": m.severity,
                    "removable": m.removable
                }
                for m in result.mechanisms
            ],
            "systemd_services": result.systemd_services,
            "cron_jobs": result.cron_jobs,
            "startup_files": result.startup_files,
            "audited_at": result.audited_at.isoformat()
        }
