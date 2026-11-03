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
            # Check if target is local
            if "/" not in result.target or not result.target.startswith("/"):
                self.logger.info("Target is not a local path, skipping systemd check")
                return

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
                            if "enabled" in parts and "running" in parts:
                                result.systemd_services.append(service_name)
                                result.mechanisms.append(PersistenceMechanism(
                                    type="systemd",
                                    location=service_name,
                                    description=f"Systemd service: {service_name}",
                                    severity="medium",
                                    removable=True
                                ))

            self.logger.info(f"Found {len(result.systemd_services)} systemd services")

        except Exception as e:
            self.logger.warning(f"Systemd check failed: {e}")

        except Exception as e:
            self.logger.error(f"Systemd check failed: {e}")

    async def _check_cron_jobs(self, result: PersistenceAuditResult) -> None:
        """Check cron jobs for persistence."""
        # Check if target is local
        if "/" not in result.target or not result.target.startswith("/"):
            self.logger.info("Target is not a local path, skipping cron check")
            return

        cron_paths = [
            "/etc/crontab",
            "/etc/cron.d/",
            "/var/spool/cron/crontabs/",
            "/root/.crontab"
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

            except Exception as e:
                self.logger.debug(f"Cron check failed for {path}: {e}")

        self.logger.info(f"Found {len(result.cron_jobs)} cron job locations")

    async def _check_startup_files(self, result: PersistenceAuditResult) -> None:
        """Check startup files for persistence."""
        # Check if target is local
        if "/" not in result.target or not result.target.startswith("/"):
            self.logger.info("Target is not a local path, skipping startup file check")
            return

        startup_files = [
            "/etc/rc.local",
            "/etc/rc.d/",
            "/etc/init.d/",
            "/etc/systemd/system/"
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
                    result.mechanisms.append(PersistenceMechanism(
                        type="startup",
                        location=path,
                        description="Startup file found",
                        severity="low",
                        removable=True
                    ))

            except Exception as e:
                self.logger.debug(f"Startup file check failed for {path}: {e}")

        self.logger.info(f"Found {len(result.startup_files)} startup file locations")

    async def _check_profile_files(self, result: PersistenceAuditResult) -> None:
        """Check profile files for persistence."""
        # Check if target is local
        if "/" not in result.target or not result.target.startswith("/"):
            self.logger.info("Target is not a local path, skipping profile check")
            return

        profile_files = [
            "/etc/profile",
            "/etc/profile.d/",
            "/root/.profile"
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

            except Exception as e:
                self.logger.debug(f"Profile check failed for {path}: {e}")

        self.logger.info(f"Profile check complete")

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
