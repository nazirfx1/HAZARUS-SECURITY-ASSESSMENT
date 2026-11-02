"""
HAZARUS Segmentation Audit
Network segmentation and trust boundary audit.
"""

import asyncio
import logging
import subprocess
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import ipaddress


@dataclass
class SegmentationIssue:
    """Network segmentation issue."""
    type: str
    source: str
    destination: str
    description: str
    severity: str


@dataclass
class SegmentationAuditResult:
    """Segmentation audit result."""
    target: str
    issues: List[SegmentationIssue] = field(default_factory=list)
    network_interfaces: List[str] = field(default_factory=list)
    routing_table: List[str] = field(default_factory=list)
    firewall_rules: List[str] = field(default_factory=list)
    audited_at: datetime = None

    def __post_init__(self):
        if self.audited_at is None:
            self.audited_at = datetime.utcnow()


class SegmentationAudit:
    """Segmentation audit module."""

    def __init__(self):
        self.logger = logging.getLogger("hazarus.segmentation_audit")

    async def audit(self, target: str) -> SegmentationAuditResult:
        """Audit network segmentation from target."""
        self.logger.info(f"Auditing segmentation from {target}")

        result = SegmentationAuditResult(target=target)

        try:
            # Check network interfaces
            await self._check_network_interfaces(result)

            # Check routing table
            await self._check_routing_table(result)

            # Check firewall rules
            await self._check_firewall_rules(result)

            # Check for cross-network access
            await self._check_cross_network_access(result)

            self.logger.info(f"Segmentation audit complete: {len(result.issues)} issues")

        except Exception as e:
            self.logger.error(f"Segmentation audit failed: {e}")

        return result

    async def _check_network_interfaces(self, result: SegmentationAuditResult) -> None:
        """Check network interfaces."""
        try:
            process = await asyncio.create_subprocess_exec(
                "ip", "addr",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                interfaces = stdout.decode().strip().split("\n")
                result.network_interfaces = [i for i in interfaces if i and "inet" in i]

        except Exception as e:
            self.logger.error(f"Network interface check failed: {e}")

    async def _check_routing_table(self, result: SegmentationAuditResult) -> None:
        """Check routing table."""
        try:
            process = await asyncio.create_subprocess_exec(
                "ip", "route",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                routes = stdout.decode().strip().split("\n")
                result.routing_table = [r for r in routes if r]

        except Exception as e:
            self.logger.error(f"Routing table check failed: {e}")

    async def _check_firewall_rules(self, result: SegmentationAuditResult) -> None:
        """Check firewall rules."""
        try:
            process = await asyncio.create_subprocess_exec(
                "iptables", "-L", "-n",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                rules = stdout.decode().strip().split("\n")
                result.firewall_rules = [r for r in rules if r and not r.startswith("Chain")]

        except Exception as e:
            self.logger.error(f"Firewall rules check failed: {e}")

    async def _check_cross_network_access(self, result: SegmentationAuditResult) -> None:
        """Check for unrestricted cross-network access."""
        # Check for default allow rules
        for rule in result.firewall_rules:
            if "ACCEPT" in rule and "0.0.0.0/0" in rule:
                result.issues.append(SegmentationIssue(
                    type="unrestricted_access",
                    source="any",
                    destination="any",
                    description="Firewall allows unrestricted access",
                    severity="high"
                ))

    def to_dict(self, result: SegmentationAuditResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": result.target,
            "issues": [
                {
                    "type": i.type,
                    "source": i.source,
                    "destination": i.destination,
                    "description": i.description,
                    "severity": i.severity
                }
                for i in result.issues
            ],
            "network_interfaces": result.network_interfaces,
            "routing_table": result.routing_table,
            "firewall_rules": result.firewall_rules,
            "audited_at": result.audited_at.isoformat()
        }
