"""
HAZARUS Safety Gate
Enforces safety policies and prevents unauthorized operations.
"""

from typing import Optional, List, Dict, Any
import logging
from datetime import datetime

from .scope import ScopeManager
from .authorization import AuthorizationManager


class SafetyError(Exception):
    """Safety-related errors."""
    pass


class SafetyGate:
    """
    Enforces safety policies before allowing operations.
    Validates scope, authorization, and operational constraints.
    """

    def __init__(self, scope_manager: ScopeManager, auth_manager: AuthorizationManager):
        self.scope_manager = scope_manager
        self.auth_manager = auth_manager
        self.logger = logging.getLogger("hazarus.safety_gate")

        self._request_count = 0
        self._blocked_operations = 0

    async def validate_operation(
        self,
        operation: str,
        targets: List[str],
        auth_id: Optional[str] = None,
        port: Optional[int] = None
    ) -> bool:
        """
        Validate that an operation is safe to execute.
        Checks scope, authorization, rate limits, and time windows.
        """
        self.logger.debug(f"Validating operation: {operation} on {len(targets)} targets")

        # Validate scope
        if not self.scope_manager.validate_targets(targets):
            self.logger.error("Scope validation failed")
            self._blocked_operations += 1
            raise SafetyError("Target(s) not in authorized scope")

        # Validate port if specified
        if port is not None and not self.scope_manager.validate_port(port):
            self.logger.error(f"Port {port} not in authorized scope")
            self._blocked_operations += 1
            raise SafetyError(f"Port {port} not authorized")

        # Validate assessment window
        if not self.scope_manager.validate_assessment_window():
            self.logger.error("Outside authorized assessment window")
            self._blocked_operations += 1
            raise SafetyError("Outside authorized assessment window")

        # Validate authorization if provided
        if auth_id and not self.auth_manager.validate_authorization(auth_id):
            self.logger.error(f"Authorization {auth_id} invalid")
            self._blocked_operations += 1
            raise SafetyError("Authorization invalid or expired")

        # Check rate limits
        if not self.scope_manager.check_rate_limit(self._request_count):
            self.logger.error("Rate limit exceeded")
            self._blocked_operations += 1
            raise SafetyError("Rate limit exceeded")

        self._request_count += 1
        self.logger.debug(f"Operation validated (request #{self._request_count})")
        return True

    async def validate_exploitation(
        self,
        exploit_id: str,
        target: str,
        auth_id: str,
        lab_only: bool = False
    ) -> bool:
        """
        Validate that an exploitation operation is authorized.
        Requires explicit authorization and additional safety checks.
        """
        self.logger.warning(f"Validating exploitation: {exploit_id} against {target}")

        # Standard validation
        await self.validate_operation("exploitation", [target], auth_id)

        # Additional exploitation-specific checks
        if lab_only:
            # Verify target is in lab environment
            if not self._is_lab_target(target):
                self.logger.error(f"Target {target} not in lab environment")
                self._blocked_operations += 1
                raise SafetyError("Exploitation only allowed in lab environment")

        self.logger.info(f"Exploitation approved: {exploit_id} against {target}")
        return True

    def _is_lab_target(self, target: str) -> bool:
        """Check if target is in a lab environment."""
        import ipaddress

        # Default lab CIDR ranges
        lab_ranges = [
            "192.168.100.0/24",
            "10.0.100.0/24",
            "172.16.100.0/24"
        ]

        try:
            target_ip = ipaddress.ip_address(target)
            for lab_range in lab_ranges:
                network = ipaddress.ip_network(lab_range)
                if target_ip in network:
                    return True
        except ValueError:
            # Not an IP address, check against domain list
            lab_domains = ["lab.local", "test.local", "internal.lab"]
            for domain in lab_domains:
                if target.endswith(domain):
                    return True

        return False

    def emergency_stop(self) -> None:
        """Emergency stop - block all further operations."""
        self.logger.critical("EMERGENCY STOP ACTIVATED")
        self._blocked_operations += 1
        raise SafetyError("Emergency stop activated")

    def get_stats(self) -> Dict[str, int]:
        """Get safety gate statistics."""
        return {
            "total_requests": self._request_count,
            "blocked_operations": self._blocked_operations,
            "allowed_operations": self._request_count - self._blocked_operations
        }

    def reset_stats(self) -> None:
        """Reset statistics."""
        self._request_count = 0
        self._blocked_operations = 0
        self.logger.debug("Safety gate stats reset")
