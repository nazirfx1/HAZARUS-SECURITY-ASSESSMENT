"""
HAZARUS Lateral Movement Audit
Lateral movement pathway analysis.
"""

import asyncio
import logging
import subprocess
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, UTC


@dataclass
class LateralPath:
    """Lateral movement pathway."""
    source: str
    destination: str
    method: str
    accessible: bool
    credentials: List[str] = field(default_factory=list)


@dataclass
class LateralMovementResult:
    """Lateral movement audit result."""
    target: str
    paths: List[LateralPath] = field(default_factory=list)
    network_hosts: List[str] = field(default_factory=list)
    trust_relationships: List[str] = field(default_factory=list)
    audited_at: datetime = None

    def __post_init__(self):
        if self.audited_at is None:
            self.audited_at = datetime.now(UTC)


class LateralMovementAudit:
    """Lateral movement audit module."""

    def __init__(self):
        self.logger = logging.getLogger("hazarus.lateral_movement_audit")

    async def audit(self, target: str) -> LateralMovementResult:
        """Audit lateral movement pathways from target."""
        self.logger.info(f"Auditing lateral movement from {target}")

        result = LateralMovementResult(target=target)

        try:
            # Discover network hosts
            await self._discover_network_hosts(result)

            # Check SMB shares
            await self._check_smb_shares(result)

            # Check SSH known hosts
            await self._check_ssh_known_hosts(result)

            # Check cached credentials
            await self._check_cached_credentials(result)

            self.logger.info(f"Lateral movement audit complete: {len(result.paths)} paths")

        except Exception as e:
            self.logger.error(f"Lateral movement audit failed: {e}")

        return result

    async def _discover_network_hosts(self, result: LateralMovementResult) -> None:
        """Discover hosts on the network."""
        try:
            # Check if target is an IP/CIDR for network discovery
            import ipaddress
            try:
                ipaddress.ip_network(result.target, strict=False)
                is_network = True
            except:
                is_network = False

            if not is_network:
                self.logger.info("Target is not a network range, skipping network host discovery")
                result.findings = []
                return

            process = await asyncio.create_subprocess_exec(
                "arp", "-a",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                lines = stdout.decode().strip().split("\n")
                hosts = []

                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1].strip("()")
                        if ip and ip != "incomplete":
                            hosts.append(ip)

                result.network_hosts = list(set(hosts))
                self.logger.info(f"Discovered {len(result.network_hosts)} network hosts")
            else:
                self.logger.warning(f"ARP scan failed: {stderr.decode()}")

        except Exception as e:
            self.logger.error(f"Network discovery failed: {e}")

    async def _check_smb_shares(self, result: LateralMovementResult) -> None:
        """Check for accessible SMB shares."""
        try:
            # Check if smbclient is available
            proc = await asyncio.create_subprocess_exec(
                "which", "smbclient",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()

            if proc.returncode != 0:
                self.logger.info("smbclient not available, skipping SMB share check")
                return

            process = await asyncio.create_subprocess_exec(
                "smbclient", "-L", "localhost",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                shares = stdout.decode().strip().split("\n")
                result.trust_relationships = [s for s in shares if s and "Share" not in s]
                self.logger.info(f"Found {len(result.trust_relationships)} SMB shares")

        except Exception as e:
            self.logger.warning(f"SMB share check failed: {e}")

    async def _check_ssh_known_hosts(self, result: LateralMovementResult) -> None:
        """Check SSH known hosts for lateral movement paths."""
        try:
            import os
            known_hosts = os.path.expanduser("~/.ssh/known_hosts")
            
            if os.path.exists(known_hosts):
                with open(known_hosts, "r") as f:
                    hosts = f.readlines()
                
                for host in hosts:
                    if host.strip() and not host.startswith("#"):
                        host_parts = host.split()[0]
                        result.paths.append(LateralPath(
                            source=result.target,
                            destination=host_parts,
                            method="ssh",
                            accessible=True
                        ))
                
                self.logger.info(f"Found {len(result.paths)} SSH known hosts")
            else:
                self.logger.info("No SSH known hosts file found")

        except Exception as e:
            self.logger.warning(f"SSH known hosts check failed: {e}")

    async def _check_cached_credentials(self, result: LateralMovementResult) -> None:
        """Check for cached credentials that could enable lateral movement."""
        try:
            import os
            # Check common credential cache locations
            credential_files = [
                "~/.aws/credentials",
                "~/.docker/config.json",
                "~/.git-credentials",
                "~/.netrc"
            ]
            
            for cred_file in credential_files:
                cred_path = os.path.expanduser(cred_file)
                if os.path.exists(cred_path):
                    result.trust_relationships.append(f"Credential file: {cred_file}")
                    self.logger.warning(f"Found credential file: {cred_file}")

        except Exception as e:
            self.logger.warning(f"Cached credentials check failed: {e}")
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                shares = stdout.decode().strip().split("\n")
                for share in shares:
                    if "Share" in share or "Disk" in share:
                        result.paths.append(LateralPath(
                            source=result.target,
                            destination="SMB Share",
                            method="SMB",
                            accessible=True
                        ))

        except Exception:
            pass

    async def _check_ssh_known_hosts(self, result: LateralMovementResult) -> None:
        """Check SSH known_hosts for lateral movement targets."""
        ssh_paths = ["/root/.ssh/known_hosts", "/home/*/.ssh/known_hosts"]

        for path in ssh_paths:
            try:
                process = await asyncio.create_subprocess_exec(
                    "cat", path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()

                if process.returncode == 0:
                    hosts = stdout.decode().strip().split("\n")
                    for host in hosts:
                        if host and not host.startswith("#"):
                            result.paths.append(LateralPath(
                                source=result.target,
                                destination=host.split()[0],
                                method="SSH",
                                accessible=True
                            ))

            except Exception:
                pass

    async def _check_cached_credentials(self, result: LateralMovementResult) -> None:
        """Check for cached credentials that could enable lateral movement."""
        # Check common credential cache locations for indicators only
        # Never extract or display actual credentials
        credential_indicators = [
            "/root/.dbus-keyrings/",
            "/home/*/.dbus-keyrings/",
            "/root/.gnupg/",
            "/home/*/.gnupg/",
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers"
        ]

        for pattern in credential_indicators:
            try:
                process = await asyncio.create_subprocess_exec(
                    "bash", "-c", f"ls -la {pattern} 2>/dev/null",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()

                if process.returncode == 0 and stdout.strip():
                    # Found credential cache indicator - report path only
                    result.paths.append(LateralPath(
                        source=result.target,
                        destination="Credential Cache",
                        method="Cached Credentials",
                        accessible=True,
                        credentials=[f"Indicator found at: {pattern}"]
                    ))
                    self.logger.warning(f"Credential cache indicator found: {pattern}")

            except Exception as e:
                self.logger.debug(f"Could not check {pattern}: {e}")

    def to_dict(self, result: LateralMovementResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": result.target,
            "paths": [
                {
                    "source": p.source,
                    "destination": p.destination,
                    "method": p.method,
                    "accessible": p.accessible,
                    "credentials": p.credentials
                }
                for p in result.paths
            ],
            "network_hosts": result.network_hosts,
            "trust_relationships": result.trust_relationships,
            "audited_at": result.audited_at.isoformat()
        }
