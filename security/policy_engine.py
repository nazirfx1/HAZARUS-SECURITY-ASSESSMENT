"""
HAZARUS Policy Engine
Evaluates security policies and operational constraints.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import logging


class PolicyDecision(Enum):
    """Policy decision."""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    REQUIRE_ADDITIONAL_CONTROLS = "require_additional_controls"


@dataclass
class PolicyResult:
    """Result of a policy evaluation."""
    decision: PolicyDecision
    reason: str
    required_controls: List[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.required_controls is None:
            self.required_controls = []
        if self.metadata is None:
            self.metadata = {}


class PolicyEngine:
    """
    Evaluates security policies for assessment operations.
    Enforces operational constraints and risk-based controls.
    """

    def __init__(self):
        self.logger = logging.getLogger("hazarus.policy_engine")
        self._policies: Dict[str, Dict[str, Any]] = {}
        self._load_default_policies()

    def _load_default_policies(self) -> None:
        """Load default security policies."""
        self._policies = {
            "exploitation": {
                "requires_approval": True,
                "lab_only": True,
                "risk_threshold": "high",
                "required_controls": ["timeout", "rollback", "evidence_capture"]
            },
            "privilege_escalation": {
                "requires_approval": True,
                "lab_only": True,
                "risk_threshold": "critical",
                "required_controls": ["timeout", "cleanup", "audit_log"]
            },
            "data_exfiltration_simulation": {
                "requires_approval": True,
                "synthetic_data_only": True,
                "risk_threshold": "high",
                "required_controls": ["data_volume_limit", "egress_monitoring"]
            },
            "persistence_simulation": {
                "requires_approval": True,
                "lab_only": True,
                "temporary_only": True,
                "required_controls": ["auto_cleanup", "clear_labeling"]
            },
            "aggressive_scanning": {
                "requires_approval": True,
                "risk_threshold": "medium",
                "required_controls": ["rate_limit", "notification"]
            }
        }

    def evaluate_operation(
        self,
        operation_type: str,
        context: Dict[str, Any]
    ) -> PolicyResult:
        """
        Evaluate an operation against security policies.
        """
        self.logger.debug(f"Evaluating policy for operation: {operation_type}")

        policy = self._policies.get(operation_type, {})

        # Check if operation type is defined
        if not policy:
            return PolicyResult(
                decision=PolicyDecision.ALLOW,
                reason="No specific policy defined for this operation"
            )

        # Check for approval requirement
        if policy.get("requires_approval"):
            if not context.get("approved"):
                return PolicyResult(
                    decision=PolicyDecision.REQUIRE_APPROVAL,
                    reason=f"Operation {operation_type} requires explicit approval",
                    required_controls=policy.get("required_controls", [])
                )

        # Check lab-only requirement
        if policy.get("lab_only"):
            if not context.get("is_lab_environment"):
                return PolicyResult(
                    decision=PolicyDecision.DENY,
                    reason=f"Operation {operation_type} only allowed in lab environment"
                )

        # Check synthetic data requirement
        if policy.get("synthetic_data_only"):
            if not context.get("using_synthetic_data"):
                return PolicyResult(
                    decision=PolicyDecision.DENY,
                    reason=f"Operation {operation_type} requires synthetic data only"
                )

        # Check temporary-only requirement
        if policy.get("temporary_only"):
            if not context.get("is_temporary"):
                return PolicyResult(
                    decision=PolicyDecision.DENY,
                    reason=f"Operation {operation_type} must be temporary"
                )

        # Check risk threshold
        risk_threshold = policy.get("risk_threshold", "low")
        context_risk = context.get("risk_level", "low")

        risk_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        if risk_levels.get(context_risk, 0) > risk_levels.get(risk_threshold, 0):
            return PolicyResult(
                decision=PolicyDecision.REQUIRE_ADDITIONAL_CONTROLS,
                reason=f"Risk level {context_risk} exceeds threshold {risk_threshold}",
                required_controls=policy.get("required_controls", [])
            )

        # Operation allowed
        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            reason="Operation complies with all policies",
            required_controls=policy.get("required_controls", [])
        )

    def add_policy(self, operation_type: str, policy: Dict[str, Any]) -> None:
        """Add or update a policy."""
        self._policies[operation_type] = policy
        self.logger.info(f"Added/updated policy for: {operation_type}")

    def remove_policy(self, operation_type: str) -> bool:
        """Remove a policy."""
        if operation_type in self._policies:
            del self._policies[operation_type]
            self.logger.info(f"Removed policy for: {operation_type}")
            return True
        return False

    def get_policy(self, operation_type: str) -> Optional[Dict[str, Any]]:
        """Get a policy by operation type."""
        return self._policies.get(operation_type)

    def get_all_policies(self) -> Dict[str, Dict[str, Any]]:
        """Get all policies."""
        return self._policies.copy()
