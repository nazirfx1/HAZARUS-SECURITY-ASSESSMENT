"""
HAZARUS Policy Engine Tests
Tests for policy evaluation and enforcement.
"""

import pytest
from security.policy_engine import PolicyEngine, PolicyResult, PolicyDecision


def test_policy_engine_initialization():
    """Test policy engine initialization."""
    engine = PolicyEngine()

    assert engine is not None
    assert len(engine._policies) > 0
    assert "exploitation" in engine._policies
    assert "privilege_escalation" in engine._policies


def test_policy_engine_evaluate_operation_no_policy():
    """Test evaluating operation with no defined policy."""
    engine = PolicyEngine()

    result = engine.evaluate_operation(
        operation_type="undefined_operation",
        context={}
    )

    assert result.decision == PolicyDecision.ALLOW
    assert "No specific policy defined" in result.reason


def test_policy_engine_evaluate_operation_requires_approval():
    """Test evaluating operation that requires approval."""
    engine = PolicyEngine()

    # Without approval
    result = engine.evaluate_operation(
        operation_type="exploitation",
        context={"approved": False}
    )

    assert result.decision == PolicyDecision.REQUIRE_APPROVAL
    assert "requires explicit approval" in result.reason

    # With approval
    result = engine.evaluate_operation(
        operation_type="exploitation",
        context={"approved": True, "is_lab_environment": True}
    )

    assert result.decision == PolicyDecision.ALLOW


def test_policy_engine_evaluate_operation_lab_only():
    """Test evaluating lab-only operation."""
    engine = PolicyEngine()

    # Not in lab
    result = engine.evaluate_operation(
        operation_type="exploitation",
        context={"approved": True, "is_lab_environment": False}
    )

    assert result.decision == PolicyDecision.DENY
    assert "only allowed in lab environment" in result.reason

    # In lab
    result = engine.evaluate_operation(
        operation_type="exploitation",
        context={"approved": True, "is_lab_environment": True}
    )

    assert result.decision == PolicyDecision.ALLOW


def test_policy_engine_evaluate_operation_synthetic_data_only():
    """Test evaluating operation requiring synthetic data."""
    engine = PolicyEngine()

    # Not using synthetic data
    result = engine.evaluate_operation(
        operation_type="data_exfiltration_simulation",
        context={"approved": True, "using_synthetic_data": False}
    )

    assert result.decision == PolicyDecision.DENY
    assert "requires synthetic data only" in result.reason

    # Using synthetic data
    result = engine.evaluate_operation(
        operation_type="data_exfiltration_simulation",
        context={"approved": True, "using_synthetic_data": True}
    )

    assert result.decision == PolicyDecision.ALLOW


def test_policy_engine_evaluate_operation_temporary_only():
    """Test evaluating operation requiring temporary execution."""
    engine = PolicyEngine()

    # Not temporary
    result = engine.evaluate_operation(
        operation_type="persistence_simulation",
        context={"approved": True, "is_lab_environment": True, "is_temporary": False}
    )

    assert result.decision == PolicyDecision.DENY
    assert "must be temporary" in result.reason

    # Temporary
    result = engine.evaluate_operation(
        operation_type="persistence_simulation",
        context={"approved": True, "is_lab_environment": True, "is_temporary": True}
    )

    assert result.decision == PolicyDecision.ALLOW


def test_policy_engine_evaluate_operation_risk_threshold():
    """Test evaluating operation against risk threshold."""
    engine = PolicyEngine()

    # Risk exceeds threshold
    result = engine.evaluate_operation(
        operation_type="aggressive_scanning",
        context={"approved": True, "risk_level": "critical"}
    )

    assert result.decision == PolicyDecision.REQUIRE_ADDITIONAL_CONTROLS
    assert "exceeds threshold" in result.reason

    # Risk within threshold
    result = engine.evaluate_operation(
        operation_type="aggressive_scanning",
        context={"approved": True, "risk_level": "low"}
    )

    assert result.decision == PolicyDecision.ALLOW


def test_policy_engine_add_policy():
    """Test adding a custom policy."""
    engine = PolicyEngine()

    custom_policy = {
        "requires_approval": True,
        "risk_threshold": "medium",
        "required_controls": ["monitoring"]
    }

    engine.add_policy("custom_operation", custom_policy)

    assert "custom_operation" in engine._policies
    assert engine._policies["custom_operation"] == custom_policy


def test_policy_engine_remove_policy():
    """Test removing a policy."""
    engine = PolicyEngine()

    # Remove existing policy
    removed = engine.remove_policy("exploitation")

    assert removed is True
    assert "exploitation" not in engine._policies

    # Try to remove non-existent policy
    removed = engine.remove_policy("nonexistent")

    assert removed is False


def test_policy_engine_get_policy():
    """Test retrieving a specific policy."""
    engine = PolicyEngine()

    policy = engine.get_policy("exploitation")

    assert policy is not None
    assert policy["requires_approval"] is True
    assert policy["lab_only"] is True

    # Non-existent policy
    policy = engine.get_policy("nonexistent")

    assert policy is None


def test_policy_engine_get_all_policies():
    """Test retrieving all policies."""
    engine = PolicyEngine()

    policies = engine.get_all_policies()

    assert isinstance(policies, dict)
    assert len(policies) > 0
    assert "exploitation" in policies
    assert "privilege_escalation" in policies


def test_policy_result_required_controls():
    """Test policy result includes required controls."""
    engine = PolicyEngine()

    result = engine.evaluate_operation(
        operation_type="exploitation",
        context={"approved": False}
    )

    assert len(result.required_controls) > 0
    assert "timeout" in result.required_controls
    assert "rollback" in result.required_controls


def test_policy_result_metadata():
    """Test policy result metadata."""
    result = PolicyResult(
        decision=PolicyDecision.ALLOW,
        reason="Test",
        metadata={"key": "value"}
    )

    assert result.metadata["key"] == "value"


def test_privilege_escalation_policy():
    """Test privilege escalation specific policy."""
    engine = PolicyEngine()

    # Requires lab and approval
    result = engine.evaluate_operation(
        operation_type="privilege_escalation",
        context={"approved": True, "is_lab_environment": False}
    )

    assert result.decision == PolicyDecision.DENY

    # With all requirements met
    result = engine.evaluate_operation(
        operation_type="privilege_escalation",
        context={"approved": True, "is_lab_environment": True}
    )

    assert result.decision == PolicyDecision.ALLOW
    assert "cleanup" in result.required_controls
