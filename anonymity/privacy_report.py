"""
HAZARUS Privacy Report
Generates comprehensive privacy readiness reports.
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PrivacyReport:
    """Comprehensive privacy readiness report."""
    assessment_id: str
    privacy_mode: str = "strict"
    anonsurf_installed: bool = False
    anonsurf_running: bool = False
    tor_available: bool = False
    dns_leak_detected: bool = False
    ipv6_exposed: bool = False
    proxy_configured: bool = False
    tor_exit_ip: Optional[str] = None
    tool_proxy_support: Dict[str, bool] = field(default_factory=dict)
    privacy_status: str = "unknown"  # pass, warning, failed
    recommendations: list = field(default_factory=list)
    generated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "assessment_id": self.assessment_id,
            "privacy_mode": self.privacy_mode,
            "anonsurf_installed": self.anonsurf_installed,
            "anonsurf_running": self.anonsurf_running,
            "tor_available": self.tor_available,
            "dns_leak_detected": self.dns_leak_detected,
            "ipv6_exposed": self.ipv6_exposed,
            "proxy_configured": self.proxy_configured,
            "tor_exit_ip": self.tor_exit_ip,
            "tool_proxy_support": self.tool_proxy_support,
            "privacy_status": self.privacy_status,
            "recommendations": self.recommendations,
            "generated_at": self.generated_at.isoformat()
        }

    def generate_recommendations(self) -> None:
        """Generate privacy recommendations based on findings."""
        self.recommendations = []

        if not self.anonsurf_installed:
            self.recommendations.append("Install Anonsurf for Tor-based anonymity")

        if not self.anonsurf_running:
            self.recommendations.append("Start Anonsurf before beginning assessment")

        if not self.tor_available:
            self.recommendations.append("Verify Tor connectivity is working")

        if self.dns_leak_detected:
            self.recommendations.append("Configure DNS to route through Tor")

        if self.ipv6_exposed:
            self.recommendations.append("Disable IPv6 or configure IPv6 through Tor")

        if not self.proxy_configured:
            self.recommendations.append("Configure system proxy settings")

        # Tool-specific recommendations
        for tool, supported in self.tool_proxy_support.items():
            if not supported:
                self.recommendations.append(f"Tool {tool} may bypass proxy - use alternative")
