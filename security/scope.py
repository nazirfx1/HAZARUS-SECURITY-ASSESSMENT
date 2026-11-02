"""
HAZARUS Scope Management
Manages assessment scope and target authorization.
"""

from typing import List, Dict, Any, Optional, Set
import ipaddress
import logging
from pathlib import Path
from datetime import datetime, UTC, timezone
from dataclasses import dataclass, field
from enum import Enum
import json
import yaml
import threading
from urllib.parse import urlparse


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
        self._request_count = 0
        self._lock = threading.Lock()
        self._concurrent_operations = 0
        self._max_concurrent = 10

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
            normalized = self._normalize_target(target)
            if not self._validate_single_target(normalized):
                self.logger.error(f"Target {target} (normalized: {normalized}) is not in scope")
                return False

        self.logger.info(f"All {len(targets)} targets validated")
        return True

    def _normalize_target(self, target: str) -> str:
        """Normalize a target for comparison."""
        target = target.strip().lower()

        # Normalize domain
        if not target.startswith(("http://", "https://")):
            # Remove trailing dot
            if target.endswith("."):
                target = target[:-1]
            return target

        # Normalize URL
        parsed = urlparse(target)
        domain = parsed.netloc.split(":")[0].lower()
        if domain.endswith("."):
            domain = domain[:-1]

        # Reconstruct URL with normalized domain
        scheme = parsed.scheme
        path = parsed.path
        query = f"?{parsed.query}" if parsed.query else ""
        fragment = f"#{parsed.fragment}" if parsed.fragment else ""

        return f"{scheme}://{domain}{path}{query}{fragment}"

    def validate_redirect(self, original_target: str, redirect_target: str) -> bool:
        """
        Validate that a redirect destination is within scope.
        Prevents DNS rebinding and unauthorized redirects.
        """
        normalized_redirect = self._normalize_target(redirect_target)

        # Prevent DNS rebinding: redirect must be within same domain or explicitly allowed
        original_type = self._classify_target(original_target)
        redirect_type = self._classify_target(normalized_redirect)

        if original_type == TargetType.DOMAIN:
            # Extract original domain
            if original_target.startswith(("http://", "https://")):
                original_domain = urlparse(original_target).netloc.split(":")[0].lower()
            else:
                original_domain = original_target.lower()

            # Extract redirect domain
            if redirect_type == TargetType.URL:
                redirect_domain = urlparse(normalized_redirect).netloc.split(":")[0].lower()
            else:
                redirect_domain = normalized_redirect

            # Allow redirects within same domain or subdomains
            if redirect_domain == original_domain or redirect_domain.endswith(f".{original_domain}"):
                return self._validate_single_target(normalized_redirect)

            # Otherwise, redirect must be explicitly in scope
            return self._validate_single_target(normalized_redirect)

        # For IPs and other types, redirect must be explicitly in scope
        return self._validate_single_target(normalized_redirect)

    def is_wildcard_safe(self, domain: str) -> bool:
        """
        Check if a wildcard domain rule would authorize unrelated domains.
        Prevents overly broad *.example.com rules from authorizing unrelated sites.
        """
        if not self.config:
            return False

        for allowed in self.config.allowed_domains:
            if allowed.startswith("*."):
                base_domain = allowed[2:]
                # Check if the target domain ends with the base
                if domain.endswith(base_domain):
                    # Ensure it's actually a subdomain, not the base itself or unrelated
                    parts = domain.rstrip(".").split(".")
                    if len(parts) > len(base_domain.split(".")):
                        return True
                    else:
                        self.logger.warning(f"Wildcard {allowed} would authorize unrelated domain {domain}")
                        return False

        return False

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

        # Normalize domain
        domain = domain.lower().rstrip(".")

        # Check explicit allowlist
        if domain in self.config.allowed_domains:
            return True

        # Check subdomain matches with wildcard safety
        for allowed in self.config.allowed_domains:
            allowed_norm = allowed.lower().rstrip(".")

            if allowed_norm.startswith("*."):
                # Wildcard rule - check safety first
                base_domain = allowed_norm[2:]
                if domain == base_domain or domain.endswith(f".{base_domain}"):
                    # Verify it's actually a subdomain, not the base or unrelated
                    domain_parts = domain.split(".")
                    base_parts = base_domain.split(".")
                    if len(domain_parts) > len(base_parts):
                        return True
                    else:
                        self.logger.warning(f"Wildcard {allowed} would authorize base domain {domain}")
                        continue
            else:
                # Exact match or subdomain
                if domain == allowed_norm or domain.endswith(f".{allowed_norm}"):
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

        # Default-deny: if ports are specified, only those are allowed
        if not self.config.allowed_ports:
            self.logger.warning("No ports explicitly allowed - treating as restricted")
            return False

        return port in self.config.allowed_ports

    def validate_assessment_window(self) -> bool:
        """
        Validate that current time is within assessment window.
        Handles timezone-aware windows and overnight assessments.
        """
        if not self.config or not self.config.assessment_window:
            return True  # No time restrictions

        window = self.config.assessment_window
        if not window.get("start") or not window.get("end"):
            return True

        try:
            now = datetime.now(UTC)

            # Parse window times - assume UTC if no timezone specified
            start_str = window["start"]
            end_str = window["end"]

            if "T" in start_str:
                start = datetime.fromisoformat(start_str)
                if start.tzinfo is None:
                    start = start.replace(tzinfo=UTC)
            else:
                # Time-only window for daily assessments
                start_hour, start_minute = map(int, start_str.split(":"))
                start = now.replace(hour=start_hour, minute=start_minute, second=0, microsecond=0)

            if "T" in end_str:
                end = datetime.fromisoformat(end_str)
                if end.tzinfo is None:
                    end = end.replace(tzinfo=UTC)
            else:
                # Time-only window for daily assessments
                end_hour, end_minute = map(int, end_str.split(":"))
                end = now.replace(hour=end_hour, minute=end_minute, second=0, microsecond=0)

            # Handle overnight windows (end < start means next day)
            if end <= start:
                # Window spans midnight
                if now >= start or now <= end:
                    return True
            else:
                # Normal window within same day
                if start <= now <= end:
                    return True

            self.logger.warning(f"Current time {now} outside assessment window {start} to {end}")
            return False

        except Exception as e:
            self.logger.error(f"Invalid assessment window: {e}")
            return False

    def check_rate_limit(self, current_requests: int = None) -> bool:
        """
        Check if request limit has been exceeded.
        Atomic check using thread lock.
        """
        if not self.config:
            return False

        with self._lock:
            if current_requests is None:
                current_requests = self._request_count

            if current_requests >= self.config.request_limit:
                self.logger.error(f"Rate limit exceeded: {current_requests}/{self.config.request_limit}")
                return False

            # Also check against rate_limit (per-minute limit)
            if current_requests >= self.config.rate_limit:
                self.logger.error(f"Rate limit exceeded: {current_requests}/{self.config.rate_limit}")
                return False

            return True

    def increment_request_count(self) -> int:
        """Atomically increment request count and return new value."""
        with self._lock:
            self._request_count += 1
            return self._request_count

    def check_concurrency(self) -> bool:
        """
        Check if concurrent operation limit has been exceeded.
        Atomic check using thread lock.
        """
        with self._lock:
            if self._concurrent_operations >= self._max_concurrent:
                self.logger.error(f"Concurrency limit exceeded: {self._concurrent_operations}/{self._max_concurrent}")
                return False
            return True

    def acquire_operation_slot(self) -> bool:
        """Atomically acquire a concurrent operation slot."""
        with self._lock:
            if self._concurrent_operations >= self._max_concurrent:
                return False
            self._concurrent_operations += 1
            return True

    def release_operation_slot(self) -> None:
        """Atomically release a concurrent operation slot."""
        with self._lock:
            self._concurrent_operations = max(0, self._concurrent_operations - 1)

    def validate_operation_permission(self, operation: str) -> bool:
        """
        Validate that the operation type is permitted.
        Operation-specific permission checks.
        """
        if not self.config:
            return False

        # Define operation permissions based on intensity
        operation_permissions = {
            "low": ["recon", "scan"],
            "normal": ["recon", "scan", "web", "api"],
            "high": ["recon", "scan", "web", "api", "exploit"],
            "aggressive": ["recon", "scan", "web", "api", "exploit", "post"]
        }

        allowed_ops = operation_permissions.get(self.config.intensity, [])

        # Check if operation is in allowed set
        for allowed in allowed_ops:
            if operation.startswith(allowed):
                return True

        self.logger.error(f"Operation {operation} not permitted at intensity {self.config.intensity}")
        return False

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
