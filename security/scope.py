"""
HAZARUS Scope Management
Manages assessment scope and target authorization.
"""

from typing import List, Dict, Any, Optional, Set
import ipaddress
import logging
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
import json
import yaml


class ScopeError(Exception):
    """Scope-related errors."""
    pass


class TargetType(Enum):
    """Types of targets."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    CIDR = "cidr"
    URL = "url"


@dataclass
class ScopeConfig:
    """Scope configuration."""
    allowed_targets: List[str] = field(default_factory=list)
    allowed_domains: List[str] = field(default_factory=list)
    allowed_cidrs: List[str] = field(default_factory=list)
    excluded_targets: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)
    assessment_window: Optional[Dict[str, str]] = None
    intensity: str = "normal"
    rate_limit: int = 100
    request_limit: int = 10000
    operator_id: Optional[str] = None
    client_id: Optional[str] = None
    emergency_contact: Optional[str] = None
    notes: str = ""

    def __post_init__(self):
        if self.assessment_window is None:
            self.assessment_window = {}


class ScopeManager:
    """
    Manages assessment scope and validates targets against authorization.
    """

    def __init__(self, scope_file: str):
        self.scope_file = Path(scope_file)
        self.logger = logging.getLogger("hazarus.scope_manager")
        self.config: Optional[ScopeConfig] = None
        self._parsed_cidrs: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

    async def load_scope(self) -> bool:
        """Load scope configuration from file."""
        try:
            if not self.scope_file.exists():
                self.logger.error(f"Scope file not found: {self.scope_file}")
                return False

            with open(self.scope_file, "r") as f:
                if self.scope_file.suffix in [".yaml", ".yml"]:
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)

            self.config = ScopeConfig(**data)
            self._parse_cidrs()

            self.logger.info(f"Loaded scope from {self.scope_file}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to load scope: {e}")
            return False

    def _parse_cidrs(self) -> None:
        """Parse CIDR ranges into network objects."""
        self._parsed_cidrs = []
        if not self.config:
            return

        for cidr in self.config.allowed_cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                self._parsed_cidrs.append(network)
            except ValueError as e:
                self.logger.warning(f"Invalid CIDR {cidr}: {e}")

    def validate_targets(self, targets: List[str]) -> bool:
        """
        Validate that all targets are within scope.
        """
        if not self.config:
            self.logger.error("Scope not loaded")
            return False

        for target in targets:
            if not self._validate_single_target(target):
                self.logger.error(f"Target {target} is not in scope")
                return False

        self.logger.info(f"All {len(targets)} targets validated")
        return True

    def _validate_single_target(self, target: str) -> bool:
        """Validate a single target against scope."""
        # Check exclusions first
        if self._is_excluded(target):
            return False

        # Check if in allowed list
        target_type = self._classify_target(target)

        if target_type == TargetType.IPV4 or target_type == TargetType.IPV6:
            return self._validate_ip(target)
        elif target_type == TargetType.DOMAIN:
            return self._validate_domain(target)
        elif target_type == TargetType.CIDR:
            return self._validate_cidr(target)
        elif target_type == TargetType.URL:
            return self._validate_url(target)

        return False

    def _classify_target(self, target: str) -> TargetType:
        """Classify the type of target."""
        target = target.strip()

        # Check for CIDR
        if "/" in target:
            try:
                ipaddress.ip_network(target, strict=False)
                return TargetType.CIDR
            except ValueError:
                pass

        # Check for IPv4
        try:
            ipaddress.IPv4Address(target)
            return TargetType.IPV4
        except ValueError:
            pass

        # Check for IPv6
        try:
            ipaddress.IPv6Address(target)
            return TargetType.IPV6
        except ValueError:
            pass

        # Check for URL
        if target.startswith(("http://", "https://")):
            return TargetType.URL

        # Default to domain
        return TargetType.DOMAIN

    def _is_excluded(self, target: str) -> bool:
        """Check if target is in exclusion list."""
        if not self.config:
            return False

        for excluded in self.config.excluded_targets:
            if target == excluded or target.startswith(excluded):
                return True

        return False

    def _validate_ip(self, ip_str: str) -> bool:
        """Validate an IP address against scope."""
        if not self.config:
            return False

        # Check explicit allowlist
        if ip_str in self.config.allowed_targets:
            return True

        # Check CIDR ranges
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in self._parsed_cidrs:
                if ip in network:
                    return True
        except ValueError:
            pass

        return False

    def _validate_domain(self, domain: str) -> bool:
        """Validate a domain against scope."""
        if not self.config:
            return False

        # Check explicit allowlist
        if domain in self.config.allowed_domains:
            return True

        # Check subdomain matches
        for allowed in self.config.allowed_domains:
            if domain == allowed or domain.endswith(f".{allowed}"):
                return True

        return False

    def _validate_cidr(self, cidr_str: str) -> bool:
        """Validate a CIDR range against scope."""
        if not self.config:
            return False

        if cidr_str in self.config.allowed_cidrs:
            return True

        # Check if CIDR is within an allowed CIDR
        try:
            cidr = ipaddress.ip_network(cidr_str, strict=False)
            for network in self._parsed_cidrs:
                if cidr.subnet_of(network):
                    return True
        except ValueError:
            pass

        return False

    def _validate_url(self, url: str) -> bool:
        """Validate a URL against scope."""
        # Extract domain from URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]  # Remove port if present

        return self._validate_domain(domain)

    def validate_port(self, port: int) -> bool:
        """Validate that a port is allowed."""
        if not self.config:
            return False

        if not self.config.allowed_ports:
            return True  # No port restrictions

        return port in self.config.allowed_ports

    def validate_assessment_window(self) -> bool:
        """Validate that current time is within assessment window."""
        if not self.config or not self.config.assessment_window:
            return True  # No time restrictions

        window = self.config.assessment_window
        if not window.get("start") or not window.get("end"):
            return True

        try:
            now = datetime.utcnow()
            start = datetime.fromisoformat(window["start"])
            end = datetime.fromisoformat(window["end"])

            return start <= now <= end
        except Exception as e:
            self.logger.error(f"Invalid assessment window: {e}")
            return False

    def check_rate_limit(self, current_requests: int) -> bool:
        """Check if request limit has been exceeded."""
        if not self.config:
            return False

        return current_requests < self.config.request_limit

    def get_scope_summary(self) -> Dict[str, Any]:
        """Get a summary of the current scope."""
        if not self.config:
            return {}

        return {
            "allowed_targets": len(self.config.allowed_targets),
            "allowed_domains": len(self.config.allowed_domains),
            "allowed_cidrs": len(self.config.allowed_cidrs),
            "excluded_targets": len(self.config.excluded_targets),
            "allowed_ports": len(self.config.allowed_ports),
            "intensity": self.config.intensity,
            "rate_limit": self.config.rate_limit,
            "request_limit": self.config.request_limit,
            "operator_id": self.config.operator_id,
            "client_id": self.config.client_id,
        }

    def create_scope_template(self, output_path: Path) -> None:
        """Create a scope configuration template."""
        template = {
            "allowed_targets": ["192.168.1.100", "example.com"],
            "allowed_domains": ["example.com", "test.example.com"],
            "allowed_cidrs": ["192.168.1.0/24"],
            "excluded_targets": ["192.168.1.1", "critical.example.com"],
            "allowed_ports": [80, 443, 22, 3389],
            "assessment_window": {
                "start": "2024-01-01T00:00:00",
                "end": "2024-12-31T23:59:59"
            },
            "intensity": "normal",
            "rate_limit": 100,
            "request_limit": 10000,
            "operator_id": "operator@example.com",
            "client_id": "client-001",
            "emergency_contact": "emergency@example.com",
            "notes": "Assessment scope description"
        }

        with open(output_path, "w") as f:
            yaml.dump(template, f, default_flow_style=False)

        self.logger.info(f"Created scope template: {output_path}")
