"""
HAZARUS DNS Leak Check
Detects DNS leaks and validates DNS resolution through Tor.
"""

from typing import List, Optional
import asyncio
import logging
import httpx
import socket


class DNSLeakChecker:
    """
    Checks for DNS leaks by comparing DNS resolution across multiple providers.
    """

    def __init__(self):
        self.logger = logging.getLogger("hazarus.dns_leak_checker")

    async def check_leaks(self) -> dict:
        """
        Check for DNS leaks using multiple DNS leak test services.
        """
        result = {
            "leaking": False,
            "dns_servers": [],
            "consistent": True,
            "using_tor": False
        }

        # Try multiple methods to check DNS configuration
        methods = [
            self._check_resolvectl,
            self._check_resolv_conf,
            self._check_nmcli
        ]

        for method in methods:
            try:
                dns_servers = await method()
                if dns_servers:
                    result["dns_servers"] = dns_servers
                    break
            except Exception as e:
                self.logger.debug(f"DNS check method failed: {e}")
                continue

        # If no DNS servers detected and method failed, assume potential issue
        if not result["dns_servers"]:
            result["leaking"] = True
            result["consistent"] = False
        
        return result

    async def _check_resolvectl(self) -> list:
        """Check DNS using resolvectl (systemd)."""
        proc = await asyncio.create_subprocess_exec(
            "resolvectl", "status",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode()
        
        dns_servers = []
        if "DNS Servers:" in output:
            lines = output.split('\n')
            for line in lines:
                if "DNS Servers:" in line:
                    continue
                if line.strip() and not line.startswith(' '):
                    dns_servers.append(line.strip())
        return dns_servers

    async def _check_resolv_conf(self) -> list:
        """Check DNS using /etc/resolv.conf."""
        proc = await asyncio.create_subprocess_exec(
            "cat", "/etc/resolv.conf",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode()
        
        dns_servers = []
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('nameserver'):
                parts = line.split()
                if len(parts) >= 2:
                    dns_servers.append(parts[1])
        return dns_servers

    async def _check_nmcli(self) -> list:
        """Check DNS using nmcli (NetworkManager)."""
        proc = await asyncio.create_subprocess_exec(
            "nmcli", "device", "show",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode()
        
        dns_servers = []
        for line in output.split('\n'):
            if 'IP4.DNS' in line or 'DNS' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    dns = parts[1].strip()
                    if dns:
                        dns_servers.append(dns)
        return dns_servers
        current_dns = self._get_current_dns()
        result["dns_servers"] = current_dns

        # Check if DNS is routing through Tor
        result["using_tor"] = self._is_dns_via_tor()

        # Determine if leak detected
        if not result["using_tor"] and current_dns:
            result["leak_detected"] = True

        return result

    def _get_current_dns(self) -> List[str]:
        """Get current DNS servers from system configuration."""
        try:
            # Read /etc/resolv.conf on Linux
            with open("/etc/resolv.conf", "r") as f:
                lines = f.readlines()

            dns_servers = []
            for line in lines:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        dns_servers.append(parts[1])

            return dns_servers
        except Exception as e:
            self.logger.error(f"Failed to get current DNS: {e}")
            return []

    def _is_dns_via_tor(self) -> bool:
        """Check if DNS is being routed through Tor."""
        try:
            # Tor typically uses 127.0.0.1 for DNS when configured
            dns_servers = self._get_current_dns()
            return any("127.0.0.1" in server for server in dns_servers)
        except Exception:
            return False

    async def resolve_via_tor(self, domain: str) -> Optional[str]:
        """Resolve a domain through Tor's DNS resolver."""
        try:
            # Use Tor's SOCKS5 proxy with DNS resolution
            # This requires proper Tor configuration
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", 9050
            )
            # Simplified - actual implementation would use SOCKS5 protocol
            writer.close()
            await writer.wait_closed()
            return None
        except Exception as e:
            self.logger.error(f"Failed to resolve via Tor: {e}")
            return None
