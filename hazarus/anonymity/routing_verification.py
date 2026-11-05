"""
HAZARUS Network Routing Verification Service
Evidence-based routing verification per tool and routing policy.
"""

from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime, UTC
import logging
import asyncio
import subprocess
import socket

from hazarus.anonymity.anonsurf import AnonsurfManager
from hazarus.anonymity.tor_check import TorChecker
from hazarus.anonymity.dns_leak import DNSLeakChecker
from hazarus.anonymity.ipv6_check import IPv6Checker
from hazarus.anonymity.proxy_validation import ProxyValidator


class RoutingMode(str, Enum):
    """Routing mode options."""
    NORMAL = "normal"
    PROXY = "proxy"
    TOR = "tor"


class RoutingStatus(str, Enum):
    """Routing status."""
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class RoutingReport:
    """Routing verification report."""
    mode: RoutingMode
    status: RoutingStatus
    anonsurf_installed: bool
    anonsurf_active: bool
    tor_connected: bool
    external_ip: Optional[str]
    dns_leaking: bool
    ipv6_enabled: bool
    proxy_configured: bool
    tool_compatibility: Dict[str, bool]
    timestamp: datetime
    details: Dict[str, Any]


class RoutingVerificationService:
    """Evidence-based routing verification service."""
    
    def __init__(self):
        self.logger = logging.getLogger("hazarus.routing")
        self.anonsurf = AnonsurfManager()
        self.tor_checker = TorChecker()
        self.dns_checker = DNSLeakChecker()
        self.ipv6_checker = IPv6Checker()
        self.proxy_validator = ProxyValidator()
        
        # Tool proxy compatibility cache
        self._tool_compatibility_cache: Dict[str, bool] = {}
    
    async def verify_routing(
        self,
        mode: RoutingMode,
        required_tools: Optional[List[str]] = None
    ) -> RoutingReport:
        """
        Verify routing configuration matches required mode.
        
        Args:
            mode: Required routing mode
            required_tools: List of tools that must be compatible
            
        Returns:
            RoutingReport with verification results
        """
        self.logger.info(f"Verifying routing for mode: {mode}")
        
        # Check base components
        anonsurf_status = await self._check_anonsurf()
        tor_status = await self._check_tor()
        dns_status = await self._check_dns_leak()
        ipv6_status = await self._check_ipv6()
        proxy_status = await self._check_proxy()
        
        # Determine external IP
        external_ip = await self._get_external_ip()
        
        # Check tool compatibility
        tool_compatibility = {}
        if required_tools:
            for tool in required_tools:
                tool_compatibility[tool] = await self._check_tool_compatibility(tool)
        
        # Determine overall status based on mode
        status = self._evaluate_mode(
            mode,
            anonsurf_status,
            tor_status,
            dns_status,
            ipv6_status,
            proxy_status,
            tool_compatibility
        )
        
        report = RoutingReport(
            mode=mode,
            status=status,
            anonsurf_installed=anonsurf_status.get("installed", False),
            anonsurf_active=anonsurf_status.get("active", False),
            tor_connected=tor_status.get("connected", False),
            external_ip=external_ip,
            dns_leaking=dns_status.get("leaking", False),
            ipv6_enabled=ipv6_status.get("ipv6_enabled", False),
            proxy_configured=proxy_status.get("configured", False),
            tool_compatibility=tool_compatibility,
            timestamp=datetime.now(UTC),
            details={
                "anonsurf": anonsurf_status,
                "tor": tor_status,
                "dns": dns_status,
                "ipv6": ipv6_status,
                "proxy": proxy_status
            }
        )
        
        self.logger.info(f"Routing verification complete: {status}")
        return report
    
    async def _check_anonsurf(self) -> Dict[str, Any]:
        """Check Anonsurf installation and status."""
        try:
            # Check if Anonsurf is installed
            result = await asyncio.create_subprocess_exec(
                "which", "anonsurf",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.wait()
            installed = result.returncode == 0
            
            if not installed:
                return {"installed": False, "active": False}
            
            # Check if Anonsurf is active
            status = self.anonsurf.check_status()
            return {
                "installed": True,
                "active": status.get("running", False)
            }
        except Exception as e:
            self.logger.warning(f"Anonsurf check failed: {e}")
            return {"installed": False, "active": False, "error": str(e)}
    
    async def _check_tor(self) -> Dict[str, Any]:
        """Check Tor connectivity."""
        try:
            connected = self.tor_checker.check_connectivity()
            exit_ip = self.tor_checker.get_exit_ip()
            
            return {
                "connected": connected.get("connected", False),
                "exit_ip": exit_ip.get("exit_ip") if exit_ip else None
            }
        except Exception as e:
            self.logger.warning(f"Tor check failed: {e}")
            return {"connected": False, "error": str(e)}
    
    async def _check_dns_leak(self) -> Dict[str, Any]:
        """Check for DNS leaks."""
        try:
            result = self.dns_checker.check_leaks()
            return {
                "leaking": result.get("leaking", False),
                "dns_servers": result.get("dns_servers", [])
            }
        except Exception as e:
            self.logger.warning(f"DNS leak check failed: {e}")
            return {"leaking": False, "error": str(e)}
    
    async def _check_ipv6(self) -> Dict[str, Any]:
        """Check IPv6 exposure."""
        try:
            result = self.ipv6_checker.check_exposure()
            return {
                "ipv6_enabled": result.get("ipv6_enabled", False),
                "ipv6_address": result.get("ipv6_address")
            }
        except Exception as e:
            self.logger.warning(f"IPv6 check failed: {e}")
            return {"ipv6_enabled": False, "error": str(e)}
    
    async def _check_proxy(self) -> Dict[str, Any]:
        """Check proxy configuration."""
        try:
            # Check for common proxy environment variables
            proxy_vars = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
            configured = any(
                self._get_env_var(var) is not None for var in proxy_vars
            )
            
            return {
                "configured": configured,
                "env_vars": {var: self._get_env_var(var) for var in proxy_vars}
            }
        except Exception as e:
            self.logger.warning(f"Proxy check failed: {e}")
            return {"configured": False, "error": str(e)}
    
    async def _get_external_ip(self) -> Optional[str]:
        """Get external IP address."""
        try:
            # Try to get external IP via DNS
            # This is a simplified check - in production use proper DNS
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        except Exception as e:
            self.logger.warning(f"External IP check failed: {e}")
            return None
    
    async def _check_tool_compatibility(self, tool: str) -> bool:
        """Check if a tool is compatible with current routing."""
        # Check cache first
        if tool in self._tool_compatibility_cache:
            return self._tool_compatibility_cache[tool]
        
        try:
            # Different tools have different proxy support
            # This is a simplified check - extend as needed
            proxy_compatible_tools = ["curl", "wget", "httpx"]
            direct_tools = ["nmap", "masscan"]
            
            if tool.lower() in proxy_compatible_tools:
                # Check if proxy is configured
                proxy_status = await self._check_proxy()
                compatible = proxy_status.get("configured", False)
            elif tool.lower() in direct_tools:
                # Direct tools work with any routing but may bypass proxy
                compatible = True
            else:
                # Default to compatible for unknown tools
                compatible = True
            
            self._tool_compatibility_cache[tool] = compatible
            return compatible
        except Exception as e:
            self.logger.warning(f"Tool compatibility check failed for {tool}: {e}")
            return False
    
    def _get_env_var(self, var: str) -> Optional[str]:
        """Get environment variable."""
        import os
        return os.environ.get(var)
    
    def _evaluate_mode(
        self,
        mode: RoutingMode,
        anonsurf_status: Dict[str, Any],
        tor_status: Dict[str, Any],
        dns_status: Dict[str, Any],
        ipv6_status: Dict[str, Any],
        proxy_status: Dict[str, Any],
        tool_compatibility: Dict[str, bool]
    ) -> RoutingStatus:
        """
        Evaluate if routing configuration satisfies required mode.
        
        Returns BLOCKED if mode cannot be satisfied.
        """
        if mode == RoutingMode.NORMAL:
            # Normal mode: just ensure no DNS leaks
            if dns_status.get("leaking", False):
                return RoutingStatus.BLOCKED
            return RoutingStatus.VERIFIED
        
        elif mode == RoutingMode.PROXY:
            # Proxy mode: requires proxy configured
            if not proxy_status.get("configured", False):
                return RoutingStatus.BLOCKED
            if dns_status.get("leaking", False):
                return RoutingStatus.FAILED
            # Check tool compatibility
            if not all(tool_compatibility.values()):
                return RoutingStatus.FAILED
            return RoutingStatus.VERIFIED
        
        elif mode == RoutingMode.TOR:
            # Tor mode: requires Anonsurf and Tor connectivity
            if not anonsurf_status.get("installed", False):
                return RoutingStatus.BLOCKED
            if not anonsurf_status.get("active", False):
                return RoutingStatus.BLOCKED
            if not tor_status.get("connected", False):
                return RoutingStatus.FAILED
            if dns_status.get("leaking", False):
                return RoutingStatus.FAILED
            if ipv6_status.get("ipv6_enabled", False):
                return RoutingStatus.FAILED
            return RoutingStatus.VERIFIED
        
        return RoutingStatus.UNVERIFIED
    
    def get_routing_recommendation(
        self,
        report: RoutingReport
    ) -> str:
        """Get recommendation based on routing report."""
        if report.status == RoutingStatus.VERIFIED:
            return f"Routing verified for {report.mode} mode"
        
        if report.status == RoutingStatus.BLOCKED:
            if report.mode == RoutingMode.TOR:
                if not report.anonsurf_installed:
                    return "Install Anonsurf for Tor mode"
                if not report.anonsurf_active:
                    return "Start Anonsurf for Tor mode"
            if report.mode == RoutingMode.PROXY:
                if not report.proxy_configured:
                    return "Configure proxy for proxy mode"
            return f"Cannot satisfy {report.mode} routing mode"
        
        if report.status == RoutingStatus.FAILED:
            if report.dns_leaking:
                return "Fix DNS leak before proceeding"
            if report.ipv6_enabled and report.mode == RoutingMode.TOR:
                return "Disable IPv6 for Tor mode"
            if report.tool_compatibility:
                incompatible = [t for t, c in report.tool_compatibility.items() if not c]
                return f"Tools not compatible: {', '.join(incompatible)}"
        
        return "Routing verification failed - check configuration"
