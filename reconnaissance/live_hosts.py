"""
HAZARUS Live Host Discovery
ARP, ICMP, and IPv6 host discovery tools.
"""

import asyncio
import logging
import re
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class LiveHost:
    """Live host information."""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    response_time: Optional[float] = None
    source: str = ""  # Which tool found it


@dataclass
class LiveHostResult:
    """Live host discovery result."""
    target: str
    hosts: List[LiveHost] = field(default_factory=list)
    total_scanned: int = 0
    scan_duration: float = 0.0
    errors: List[str] = field(default_factory=list)


class LiveHostDiscovery:
    """Live host discovery module using arping, fping, and inverse_lookup6."""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.logger = logging.getLogger("hazarus.live_host_discovery")

    async def discover_hosts(
        self,
        target: str,
        use_arping: bool = True,
        use_fping: bool = True,
        use_ipv6: bool = False
    ) -> LiveHostResult:
        """Discover live hosts using multiple methods."""
        self.logger.info(f"Starting live host discovery for {target}")

        result = LiveHostResult(target=target)
        start_time = datetime.utcnow()

        # Method 1: ARP discovery (arping)
        if use_arping:
            arping_hosts = await self._arping_discovery(target)
            result.hosts.extend(arping_hosts)
            self.logger.info(f"ARPing found {len(arping_hosts)} hosts")

        # Method 2: Fast ping (fping)
        if use_fping:
            fping_hosts = await self._fping_discovery(target)
            result.hosts.extend(fping_hosts)
            self.logger.info(f"Fping found {len(fping_hosts)} hosts")

        # Method 3: IPv6 inverse lookup (inverse_lookup6)
        if use_ipv6:
            ipv6_hosts = await self._ipv6_discovery(target)
            result.hosts.extend(ipv6_hosts)
            self.logger.info(f"IPv6 discovery found {len(ipv6_hosts)} hosts")

        # Remove duplicates (keep fastest response)
        seen = {}
        for host in result.hosts:
            if host.ip not in seen or (host.response_time and (not seen[host.ip].response_time or host.response_time < seen[host.ip].response_time)):
                seen[host.ip] = host
        result.hosts = list(seen.values())

        result.scan_duration = (datetime.utcnow() - start_time).total_seconds()
        result.total_scanned = len(result.hosts)

        self.logger.info(f"Live host discovery complete: {len(result.hosts)} hosts found")
        return result

    async def _arping_discovery(self, target: str) -> List[LiveHost]:
        """Use arping for ARP-based host discovery (aggressive mode)."""
        hosts = []

        try:
            # Check if arping is available
            proc = await asyncio.create_subprocess_exec(
                "which", "arping",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()

            if proc.returncode != 0:
                self.logger.info("arping not available, skipping ARP discovery")
                return hosts

            self.logger.info(f"Running arping for {target}")

            # Detect if already running as root
            is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False

            # Build command without sudo if already root
            if is_root:
                cmd = ["arping", "-c", "3", "-w", "2", target]
            else:
                cmd = ["sudo", "arping", "-c", "3", "-w", "2", target]

            # Run arping without broadcast mode (works on more interfaces)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                self.logger.warning("arping timed out")
                return hosts

            output = stdout.decode()
            stderr_text = stderr.decode()

            if proc.returncode != 0:
                self.logger.warning(f"arping failed: {stderr_text}")
                return hosts

            # Parse arping output
            # Format: "Unicast reply from 192.168.1.1 [00:11:22:33:44:55]  1.234 ms"
            for line in output.split('\n'):
                match = re.search(r'Unicast reply from (\S+) \[([^\]]+)\]\s+([\d.]+) ms', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2)
                    response_time = float(match.group(3))

                    hosts.append(LiveHost(
                        ip=ip,
                        mac=mac,
                        response_time=response_time,
                        source="arping"
                    ))

                    self.logger.debug(f"ARPing found host: {ip} ({mac})")

        except Exception as e:
            self.logger.error(f"ARPing discovery failed: {e}")

        return hosts

    async def _fping_discovery(self, target: str) -> List[LiveHost]:
        """Use fping for fast ICMP ping discovery (aggressive mode)."""
        hosts = []

        try:
            # Check if fping is available
            proc = await asyncio.create_subprocess_exec(
                "which", "fping",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()

            if proc.returncode != 0:
                self.logger.info("fping not available, skipping ICMP discovery")
                return hosts

            self.logger.info(f"Running fping for {target}")

            # Check if already running as root
            is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False

            # Build command without -O flag (use simpler output)
            if is_root:
                cmd = ["fping", "-a", "-c", "3", "-i", "10", "-t", "500", target]
            else:
                cmd = ["sudo", "fping", "-a", "-c", "3", "-i", "10", "-t", "500", target]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                self.logger.warning("fping timed out")
                return hosts

            output = stdout.decode()
            stderr_text = stderr.decode()

            if proc.returncode != 0:
                self.logger.warning(f"fping failed: {stderr_text}")
                return hosts

            # Parse fping output
            # Format: "192.168.1.1 is alive (0.23 ms)" or "192.168.1.1 : xmt/rcv/%loss = 3/3/0%, min/avg/max = 0.23/0.25/0.28 ms"
            for line in output.split('\n'):
                # Try both formats
                match = re.search(r'(\S+) is alive \(([\d.]+) ms\)', line)
                if not match:
                    match = re.search(r'(\S+) :.*min/avg/max = ([\d.]+)/', line)
                
                if match:
                    ip = match.group(1)
                    response_time = float(match.group(2))

                    hosts.append(LiveHost(
                        ip=ip,
                        response_time=response_time,
                        source="fping"
                    ))

                    self.logger.debug(f"Fping found host: {ip}")

        except Exception as e:
            self.logger.error(f"Fping discovery failed: {e}")

        return hosts

    async def _ipv6_discovery(self, target: str) -> List[LiveHost]:
        """Use inverse_lookup6 for IPv6 discovery (aggressive mode)."""
        hosts = []

        try:
            # Check if inverse_lookup6 is available
            proc = await asyncio.create_subprocess_exec(
                "which", "atk6-inverse_lookup6",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()

            if proc.returncode != 0:
                self.logger.info("inverse_lookup6 not available, skipping IPv6 discovery")
                return hosts

            self.logger.info(f"Running inverse_lookup6 for {target}")

            # Check if already running as root
            is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False

            # Build command without -v flag (may not be supported)
            if is_root:
                cmd = ["atk6-inverse_lookup6", target]
            else:
                cmd = ["sudo", "atk6-inverse_lookup6", target]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                self.logger.warning("inverse_lookup6 timed out")
                return hosts

            output = stdout.decode()
            stderr_text = stderr.decode()

            if proc.returncode != 0:
                self.logger.warning(f"inverse_lookup6 failed: {stderr_text}")
                return hosts

            # Parse inverse_lookup6 output
            # Format varies, look for IPv6 addresses
            ipv6_pattern = r'([0-9a-fA-F:]+:[0-9a-fA-F:]+)'
            for match in re.finditer(ipv6_pattern, output):
                ip = match.group(1)
                if ':' in ip and not ip.startswith('fe80'):  # Skip link-local
                    hosts.append(LiveHost(
                        ip=ip,
                        source="inverse_lookup6"
                    ))
                    self.logger.debug(f"IPv6 discovery found host: {ip}")

        except Exception as e:
            self.logger.error(f"IPv6 discovery failed: {e}")

        return hosts

    def to_dict(self, result: LiveHostResult) -> Dict[str, Any]:
        """Convert LiveHostResult to dictionary."""
        return {
            "target": result.target,
            "hosts": [
                {
                    "ip": h.ip,
                    "mac": h.mac,
                    "hostname": h.hostname,
                    "response_time": h.response_time,
                    "source": h.source
                }
                for h in result.hosts
            ],
            "total_scanned": result.total_scanned,
            "scan_duration": result.scan_duration,
            "errors": result.errors
        }
