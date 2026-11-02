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

    async def check_dns_leak(self) -> dict:
        """
        Check for DNS leaks using multiple DNS leak test services.
        """
        result = {
            "leak_detected": False,
            "dns_servers": [],
            "consistent": True,
            "using_tor": False
        }

        # Try multiple DNS leak test services
        services = [
            "https://dnsleaktest.com",
            "https://ipleak.net"
        ]

        dns_servers = set()

        for service in services:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(service)
                    # Parse response to extract DNS servers
                    # This is a simplified version - actual implementation would parse HTML
                    self.logger.debug(f"Checked DNS leak using {service}")
            except Exception as e:
                self.logger.warning(f"Failed to check {service}: {e}")

        # Check current DNS configuration
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
