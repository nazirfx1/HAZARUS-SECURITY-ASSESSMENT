"""
HAZARUS IPv6 Check
Detects IPv6 exposure and validates IPv6 anonymity.
"""

from typing import List, Optional
import asyncio
import logging
import subprocess


class IPv6Checker:
    """
    Checks for IPv6 exposure and validates IPv6 configuration.
    """

    def __init__(self):
        self.logger = logging.getLogger("hazarus.ipv6_checker")

    async def check_ipv6_enabled(self) -> bool:
        """Check if IPv6 is enabled on the system."""
        try:
            # Check sysctl settings for IPv6 disable
            result = await asyncio.create_subprocess_exec(
                "sysctl", "-n", "net.ipv6.conf.all.disable_ipv6",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            output = stdout.decode().strip()
            
            # If net.ipv6.conf.all.disable_ipv6 = 1, IPv6 is disabled
            if output == "1":
                return False
            
            # Also check default
            result2 = await asyncio.create_subprocess_exec(
                "sysctl", "-n", "net.ipv6.conf.default.disable_ipv6",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout2, stderr2 = await result2.communicate()
            output2 = stdout2.decode().strip()
            
            if output2 == "1":
                return False
            
            # If either is 0, IPv6 is enabled
            return True
        except Exception as e:
            self.logger.error(f"Error checking IPv6: {e}")
            # Default to assuming enabled if check fails
            return True

    async def get_ipv6_addresses(self) -> List[str]:
        """Get all IPv6 addresses on the system."""
        try:
            result = await asyncio.create_subprocess_exec(
                "ip", "-6", "addr",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            output = stdout.decode()

            addresses = []
            for line in output.split("\n"):
                if "inet6" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        addresses.append(parts[1].split("/")[0])

            return addresses
        except Exception as e:
            self.logger.error(f"Error getting IPv6 addresses: {e}")
            return []

    async def has_global_ipv6(self) -> bool:
        """Check if system has global IPv6 addresses (potential leak)."""
        addresses = await self.get_ipv6_addresses()

        for addr in addresses:
            # Check if address is not link-local or unique local
            if not addr.startswith("fe80:") and not addr.startswith("fc") and not addr.startswith("fd"):
                return True

        return False

    async def check_ipv6_leak(self) -> dict:
        """
        Check for IPv6 leaks.
        """
        result = {
            "ipv6_enabled": False,
            "has_global_address": False,
            "ipv6_addresses": [],
            "leak_risk": "low"
        }

        result["ipv6_enabled"] = await self.check_ipv6_enabled()

        if result["ipv6_enabled"]:
            result["ipv6_addresses"] = await self.get_ipv6_addresses()
            result["has_global_address"] = await self.has_global_ipv6()

            if result["has_global_address"]:
                result["leak_risk"] = "high"
            elif result["ipv6_addresses"]:
                result["leak_risk"] = "medium"

        return result

    async def disable_ipv6(self) -> bool:
        """
        Disable IPv6 (requires root).
        WARNING: This is a destructive operation.
        """
        self.logger.warning("IPv6 disable operation - requires manual confirmation")
        return False

    async def check_ipv6_dns(self) -> bool:
        """Check if DNS is using IPv6."""
        try:
            result = await asyncio.create_subprocess_exec(
                "dig", "AAAA", "example.com",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Error checking IPv6 DNS: {e}")
            return False
