"""
HAZARUS Tor Check
Verifies Tor connectivity and exit node status.
"""

from typing import Optional
import asyncio
import logging
import httpx


class TorChecker:
    """
    Checks Tor connectivity and validates exit node information.
    """

    def __init__(self, tor_proxy: str = "socks5://127.0.0.1:9050"):
        self.tor_proxy = tor_proxy
        self.logger = logging.getLogger("hazarus.tor_checker")

    async def check_tor_connection(self) -> bool:
        """Check if Tor proxy is accessible."""
        try:
            async with httpx.AsyncClient(proxies={"all://": self.tor_proxy}) as client:
                response = await client.get("https://check.torproject.org/", timeout=10.0)
                return "Congratulations" in response.text or "You are using Tor" in response.text
        except Exception as e:
            self.logger.error(f"Tor connection check failed: {e}")
            return False

    async def get_exit_ip(self) -> Optional[str]:
        """Get the current Tor exit IP address."""
        try:
            async with httpx.AsyncClient(proxies={"all://": self.tor_proxy}) as client:
                response = await client.get("https://api.ipify.org?format=json", timeout=10.0)
                data = response.json()
                return data.get("ip")
        except Exception as e:
            self.logger.error(f"Failed to get exit IP: {e}")
            return None

    async def is_tor_exit_ip(self, ip: str) -> bool:
        """Check if an IP is a known Tor exit node."""
        try:
            # Use Tor Project's exit node list
            async with httpx.AsyncClient() as client:
                response = await client.get("https://check.torproject.org/exit-addresses", timeout=10.0)
                return ip in response.text
        except Exception as e:
            self.logger.error(f"Failed to check if IP is Tor exit: {e}")
            return False

    async def get_tor_info(self) -> dict:
        """Get comprehensive Tor connection information."""
        info = {
            "tor_enabled": False,
            "exit_ip": None,
            "is_exit_node": False,
            "connection_successful": False
        }

        info["connection_successful"] = await self.check_tor_connection()
        info["tor_enabled"] = info["connection_successful"]

        if info["connection_successful"]:
            info["exit_ip"] = await self.get_exit_ip()
            if info["exit_ip"]:
                info["is_exit_node"] = await self.is_tor_exit_ip(info["exit_ip"])

        return info
