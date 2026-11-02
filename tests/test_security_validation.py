"""
HAZARUS Security Validation Tests
Tests for scope enforcement, safety gates, and authorization.
"""

import pytest
import asyncio
from security.scope import ScopeManager, ScopeConfig, ScopeError, TargetType
from security.safety_gate import SafetyGate, SafetyError
from security.authorization import AuthorizationManager


@pytest.mark.asyncio
async def test_scope_validation_ipv4():
    """Test IPv4 target validation."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(
        allowed_targets=["192.168.1.100"],
        allowed_cidrs=["192.168.1.0/24"]
    )
    scope_manager._parse_cidrs()

    # Valid targets
    assert await scope_manager.validate_targets(["192.168.1.100"])
    assert await scope_manager.validate_targets(["192.168.1.50"])
    
    # Invalid target
    assert not await scope_manager.validate_targets(["10.0.0.1"])


@pytest.mark.asyncio
async def test_scope_validation_exclusion():
    """Test target exclusion."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(
        allowed_targets=["192.168.1.100"],
        excluded_targets=["192.168.1.100"]
    )

    # Target in exclusion list should be invalid
    assert not await scope_manager.validate_target("192.168.1.100")


@pytest.mark.asyncio
async def test_scope_validation_cidr():
    """Test CIDR validation."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(
        allowed_cidrs=["192.168.1.0/24", "10.0.0.0/8"]
    )
    scope_manager._parse_cidrs()

    # Valid CIDR
    assert scope_manager._is_in_cidr("192.168.1.50")
    assert scope_manager._is_in_cidr("10.0.1.1")
    
    # Invalid CIDR
    assert not scope_manager._is_in_cidr("172.16.1.1")


def test_port_validation():
    """Test port validation."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(
        allowed_ports=[80, 443, 22]
    )

    # Valid ports
    assert scope_manager.validate_port(80)
    assert scope_manager.validate_port(443)
    
    # Invalid port
    assert not scope_manager.validate_port(8080)


def test_assessment_window():
    """Test assessment window validation."""
    from datetime import datetime, UTC, timedelta

    scope_manager = ScopeManager("config/scope.yaml")
    
    # No restriction
    assert scope_manager.validate_assessment_window()

    # Valid window
    scope_manager.config = ScopeConfig(
        assessment_window={
            "start": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
            "end": (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        }
    )
    assert scope_manager.validate_assessment_window()

    # Invalid window (outside)
    scope_manager.config = ScopeConfig(
        assessment_window={
            "start": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "end": (datetime.now(UTC) + timedelta(hours=2)).isoformat()
        }
    )
    assert not scope_manager.validate_assessment_window()


def test_rate_limit():
    """Test rate limiting."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(rate_limit=100, request_limit=10000)

    # Within limit
    assert scope_manager.check_rate_limit(50)
    assert scope_manager.check_rate_limit(99)
    
    # Exceeded limit
    assert not scope_manager.check_rate_limit(100)
    assert not scope_manager.check_rate_limit(1000)


@pytest.mark.asyncio
async def test_safety_gate_validation():
    """Test safety gate operation validation."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(
        allowed_targets=["192.168.1.100"],
        allowed_ports=[80, 443]
    )
    scope_manager._parse_cidrs()

    auth_manager = AuthorizationManager()
    gate = SafetyGate(scope_manager, auth_manager)

    # Valid operation
    assert await gate.validate_operation("scan", ["192.168.1.100"], port=80)

    # Invalid target
    with pytest.raises(SafetyError):
        await gate.validate_operation("scan", ["10.0.0.1"])

    # Invalid port
    with pytest.raises(SafetyError):
        await gate.validate_operation("scan", ["192.168.1.100"], port=8080)


@pytest.mark.asyncio
async def test_safety_gate_exploitation():
    """Test safety gate exploitation validation."""
    scope_manager = ScopeManager("config/scope.yaml")
    scope_manager.config = ScopeConfig(
        allowed_targets=["192.168.100.10"]  # Lab target
    )
    scope_manager._parse_cidrs()

    auth_manager = AuthorizationManager()
    gate = SafetyGate(scope_manager, auth_manager)

    # Lab exploitation should succeed
    assert await gate.validate_exploitation("CVE-2021-44228", "192.168.100.10", "auth-001", lab_only=True)

    # Non-lab exploitation should fail
    with pytest.raises(SafetyError):
        await gate.validate_exploitation("CVE-2021-44228", "10.0.0.1", "auth-001", lab_only=True)


def test_lab_target_validation():
    """Test lab target detection."""
    scope_manager = ScopeManager("config/scope.yaml")
    auth_manager = AuthorizationManager()
    gate = SafetyGate(scope_manager, auth_manager)

    # Lab IP ranges
    assert gate._is_lab_target("192.168.100.10")
    assert gate._is_lab_target("10.0.100.50")
    assert gate._is_lab_target("172.16.100.25")
    
    # Lab domains
    assert gate._is_lab_target("test.lab")
    assert gate._is_lab_target("internal.lab")
    
    # Non-lab
    assert not gate._is_lab_target("8.8.8.8")
    assert not gate._is_lab_target("example.com")


def test_emergency_stop():
    """Test emergency stop."""
    scope_manager = ScopeManager("config/scope.yaml")
    auth_manager = AuthorizationManager()
    gate = SafetyGate(scope_manager, auth_manager)

    with pytest.raises(SafetyError, match="Emergency stop"):
        gate.emergency_stop()

    stats = gate.get_stats()
    assert stats["blocked_operations"] == 1
