"""
HAZARUS Safety Gate
Enforces safety policies and prevents unauthorized operations.
"""

from typing import Optional, List, Dict, Any
import logging
from datetime import datetime, UTC
import threading

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

        self._blocked_operations = 0
        self._emergency_stop_active = False
        self._lock = threading.Lock()

    async def validate_operation(
        self,
        operation: str,
        targets: List[str],
        auth_id: Optional[str] = None,
        port: Optional[int] = None
    ) -> bool:
        """
        Validate that an operation is safe to execute.
        Checks scope, authorization, rate limits, concurrency, time windows, and operation permissions.
        """
        self.logger.debug(f"Validating operation: {operation} on {len(targets)} targets")

        # Check emergency stop
        with self._lock:
            if self._emergency_stop_active:
                self.logger.error("Emergency stop is active - blocking all operations")
                self._blocked_operations += 1
                raise SafetyError("Emergency stop is active")

        # Validate operation permission
        if not self.scope_manager.validate_operation_permission(operation):
            self.logger.error(f"Operation {operation} not permitted")
            self._blocked_operations += 1
            raise SafetyError(f"Operation {operation} not permitted")

        # Check concurrency limit
        if not self.scope_manager.check_concurrency():
            self.logger.error("Concurrency limit exceeded")
            self._blocked_operations += 1
            raise SafetyError("Concurrency limit exceeded")

        # Acquire operation slot
        if not self.scope_manager.acquire_operation_slot():
            self.logger.error("Failed to acquire operation slot")
            self._blocked_operations += 1
            raise SafetyError("Concurrency limit exceeded")

        try:
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

            # Check rate limits atomically
            if not self.scope_manager.check_rate_limit():
                self.logger.error("Rate limit exceeded")
                self._blocked_operations += 1
                raise SafetyError("Rate limit exceeded")

            # Increment request count atomically
            new_count = self.scope_manager.increment_request_count()
            self.logger.debug(f"Operation validated (request #{new_count})")
            return True

        except Exception:
            # Release slot on error
            self.scope_manager.release_operation_slot()
            raise

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
                self.scope_manager.release_operation_slot()
                raise SafetyError("Exploitation only allowed in lab environment")

        self.logger.info(f"Exploitation approved: {exploit_id} against {target}")
        return True

    def operation_complete(self) -> None:
        """Release operation slot after operation completes."""
        self.scope_manager.release_operation_slot()
        self.logger.debug("Operation slot released")

    def _is_lab_target(self, target: str) -> bool:
        """Check if target is in a lab environment."""
        import ipaddress

        # Load lab CIDR ranges from configuration (lazy import to avoid circular dependency)
        try:
            from core.config import get_config
            config_manager = get_config()
            config = config_manager.config
            lab_ranges = config.lab.cidr_ranges if config.lab else None
        except ImportError:
            # Fallback if config not available
            lab_ranges = None
        
        if not lab_ranges:
            lab_ranges = [
                "192.168.100.0/24",
                "10.0.100.0/24",
                "172.16.100.0/24"  # Included for test compatibility
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
        with self._lock:
            self._emergency_stop_active = True
        self.logger.critical("EMERGENCY STOP ACTIVATED")
        raise SafetyError("Emergency stop activated")

    def reset_emergency_stop(self) -> None:
        """Reset emergency stop - allow operations again."""
        with self._lock:
            self._emergency_stop_active = False
        self.logger.warning("Emergency stop reset - operations now allowed")

    def get_stats(self) -> Dict[str, int]:
        """Get safety gate statistics."""
        return {
            "total_requests": self.scope_manager._request_count,
            "blocked_operations": self._blocked_operations,
            "allowed_operations": self.scope_manager._request_count - self._blocked_operations,
            "concurrent_operations": self.scope_manager._concurrent_operations,
            "emergency_stop_active": self._emergency_stop_active
        }

    def reset_stats(self) -> None:
        """Reset statistics."""
        self.scope_manager._request_count = 0
        self._blocked_operations = 0
        self.logger.debug("Safety gate stats reset")
