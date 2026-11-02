"""
HAZARUS Proxy Validation
Validates proxy configuration and detects proxy bypass.
"""

from typing import Optional, Dict, Any
import asyncio
import logging
import httpx
import os


class ProxyValidator:
    """
    Validates proxy configuration and detects tools that bypass proxy settings.
    """

    def __init__(self):
        self.logger = logging.getLogger("hazarus.proxy_validator")

    async def check_proxy_configured(self) -> bool:
        """Check if system proxy is configured."""
        http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        all_proxy = os.environ.get("ALL_PROXY") or os.environ.get("all_proxy")

        return bool(http_proxy or https_proxy or all_proxy)

    async def validate_proxy_connection(self, proxy_url: str) -> bool:
        """Validate that a proxy is accessible."""
        try:
            async with httpx.AsyncClient(proxies={"all://": proxy_url}, timeout=10.0) as client:
                response = await client.get("https://httpbin.org/ip")
                return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Proxy connection failed: {e}")
            return False

    async def detect_proxy_bypass(self, tool: str) -> bool:
        """
        Detect if a tool bypasses configured proxy settings.
        """
        # This is a simplified check - actual implementation would test each tool
        bypass_tools = {
            "curl": True,  # curl respects proxy env vars
            "wget": True,  # wget respects proxy env vars
            "python": False,  # Python requests needs explicit proxy config
            "nmap": False,  # nmap doesn't use system proxy by default
        }

        return bypass_tools.get(tool.lower(), False)

    async def check_tool_proxy_support(self, tool: str) -> bool:
        """Check if a tool supports SOCKS proxy routing."""
        proxy_support = {
            "nmap": False,  # nmap has limited proxy support
            "curl": True,   # curl supports SOCKS
            "wget": True,   # wget supports SOCKS
            "python": True, # Python can use SOCKS with libraries
            "nikto": False, # nikto has limited proxy support
            "nuclei": True, # nuclei supports proxy
        }

        return proxy_support.get(tool.lower(), False)

    async def get_proxy_info(self) -> Dict[str, Any]:
        """Get current proxy configuration."""
        return {
            "http_proxy": os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"),
            "https_proxy": os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy"),
            "all_proxy": os.environ.get("ALL_PROXY") or os.environ.get("all_proxy"),
            "no_proxy": os.environ.get("NO_PROXY") or os.environ.get("no_proxy"),
            "configured": await self.check_proxy_configured()
        }

    async def validate_tor_proxy(self) -> bool:
        """Validate Tor SOCKS proxy."""
        return await self.validate_proxy_connection("socks5://127.0.0.1:9050")
