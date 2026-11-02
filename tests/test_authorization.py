"""
HAZARUS Authorization Tests
Tests for authorization manager and authorization records.
"""

import pytest
from datetime import datetime, UTC, timedelta
from pathlib import Path
import tempfile
import shutil

from security.authorization import (
    AuthorizationManager,
    AuthorizationRecord,
    AuthStatus
)


@pytest.fixture
def temp_auth_dir():
    """Create a temporary directory for authorization tests."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_authorization_record_creation():
    """Test authorization record creation."""
    record = AuthorizationRecord(
        auth_id="test-001",
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100", "example.com"]
    )

    assert record.auth_id == "test-001"
    assert record.operator_id == "operator@example.com"
    assert record.client_id == "client-001"
    assert len(record.targets) == 2
    assert record.status == AuthStatus.PENDING
    assert record.created_at is not None


def test_authorization_record_validity():
    """Test authorization record validity checks."""
    # Valid approved authorization
    valid_record = AuthorizationRecord(
        auth_id="valid-001",
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100"],
        status=AuthStatus.APPROVED,
        approved_at=datetime.now(UTC),
        approved_by="admin",
        expires_at=datetime.now(UTC) + timedelta(hours=1)
    )
    assert valid_record.is_valid() is True

    # Expired authorization
    expired_record = AuthorizationRecord(
        auth_id="expired-001",
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100"],
        status=AuthStatus.APPROVED,
        approved_at=datetime.now(UTC),
        approved_by="admin",
        expires_at=datetime.now(UTC) - timedelta(hours=1)
    )
    assert expired_record.is_valid() is False

    # Pending authorization
    pending_record = AuthorizationRecord(
        auth_id="pending-001",
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100"],
        status=AuthStatus.PENDING
    )
    assert pending_record.is_valid() is False

    # Denied authorization
    denied_record = AuthorizationRecord(
        auth_id="denied-001",
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100"],
        status=AuthStatus.DENIED
    )
    assert denied_record.is_valid() is False

    # Revoked authorization
    revoked_record = AuthorizationRecord(
        auth_id="revoked-001",
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100"],
        status=AuthStatus.REVOKED
    )
    assert revoked_record.is_valid() is False


def test_authorization_record_to_dict():
    """Test authorization record serialization."""
    record = AuthorizationRecord(
        auth_id="test-001",
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100"],
        status=AuthStatus.APPROVED,
        approved_at=datetime.now(UTC),
        approved_by="admin",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        notes="Test authorization"
    )

    data = record.to_dict()

    assert data["auth_id"] == "test-001"
    assert data["operator_id"] == "operator@example.com"
    assert data["client_id"] == "client-001"
    assert data["status"] == "approved"
    assert data["approved_by"] == "admin"
    assert data["notes"] == "Test authorization"
    assert data["expires_at"] is not None


def test_authorization_manager_initialization(temp_auth_dir):
    """Test authorization manager initialization."""
    manager = AuthorizationManager(auth_dir=temp_auth_dir)

    assert manager.auth_dir == temp_auth_dir
    assert manager.auth_dir.exists()
    assert len(manager._records) == 0


def test_authorization_manager_create_authorization(temp_auth_dir):
    """Test creating a new authorization."""
    manager = AuthorizationManager(auth_dir=temp_auth_dir)

    record = manager.create_authorization(
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100", "example.com"],
        expires_in_days=7,
        notes="Test assessment"
    )

    assert record.status == AuthStatus.PENDING
    assert record.operator_id == "operator@example.com"
    assert record.client_id == "client-001"
    assert len(record.targets) == 2
    assert record.expires_at is not None
    assert record.notes == "Test assessment"
    assert record.auth_id in manager._records


def test_authorization_manager_approve_authorization(temp_auth_dir):
    """Test approving an authorization."""
    manager = AuthorizationManager(auth_dir=temp_auth_dir)

    record = manager.create_authorization(
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100"]
    )

    approved = manager.approve_authorization(record.auth_id, "admin")

    assert approved is True
    assert manager._records[record.auth_id].status == AuthStatus.APPROVED
    assert manager._records[record.auth_id].approved_by == "admin"
    assert manager._records[record.auth_id].approved_at is not None


def test_authorization_manager_deny_authorization(temp_auth_dir):
    """Test denying an authorization."""
    manager = AuthorizationManager(auth_dir=temp_auth_dir)

    record = manager.create_authorization(
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100"]
    )

    denied = manager.deny_authorization(record.auth_id, "Insufficient documentation")

    assert denied is True
    assert manager._records[record.auth_id].status == AuthStatus.DENIED
    assert manager._records[record.auth_id].notes == "Insufficient documentation"


def test_authorization_manager_revoke_authorization(temp_auth_dir):
    """Test revoking an authorization."""
    manager = AuthorizationManager(auth_dir=temp_auth_dir)

    record = manager.create_authorization(
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100"]
    )
    manager.approve_authorization(record.auth_id, "admin")

    revoked = manager.revoke_authorization(record.auth_id)

    assert revoked is True
    assert manager._records[record.auth_id].status == AuthStatus.REVOKED


def test_authorization_manager_validate_authorization(temp_auth_dir):
    """Test validating an authorization."""
    manager = AuthorizationManager(auth_dir=temp_auth_dir)

    record = manager.create_authorization(
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100"],
        expires_in_days=1
    )

    # Pending authorization should be invalid
    assert manager.validate_authorization(record.auth_id) is False

    # Approve it
    manager.approve_authorization(record.auth_id, "admin")

    # Now it should be valid
    assert manager.validate_authorization(record.auth_id) is True

    # Non-existent authorization should be invalid
    assert manager.validate_authorization("nonexistent") is False


def test_authorization_manager_get_authorization(temp_auth_dir):
    """Test retrieving an authorization."""
    manager = AuthorizationManager(auth_dir=temp_auth_dir)

    record = manager.create_authorization(
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100"]
    )

    retrieved = manager.get_authorization(record.auth_id)

    assert retrieved is not None
    assert retrieved.auth_id == record.auth_id
    assert retrieved.operator_id == record.operator_id

    # Non-existent should return None
    assert manager.get_authorization("nonexistent") is None


def test_authorization_manager_get_by_operator(temp_auth_dir):
    """Test retrieving authorizations by operator."""
    manager = AuthorizationManager(auth_dir=temp_auth_dir)

    record1 = manager.create_authorization(
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100"]
    )

    record2 = manager.create_authorization(
        operator_id="operator@example.com",
        client_id="client-002",
        targets=["192.168.1.200"]
    )

    record3 = manager.create_authorization(
        operator_id="other@example.com",
        client_id="client-003",
        targets=["192.168.1.300"]
    )

    operator_records = manager.get_authorizations_by_operator("operator@example.com")

    assert len(operator_records) == 2
    assert record1.auth_id in [r.auth_id for r in operator_records]
    assert record2.auth_id in [r.auth_id for r in operator_records]
    assert record3.auth_id not in [r.auth_id for r in operator_records]


def test_authorization_manager_get_by_client(temp_auth_dir):
    """Test retrieving authorizations by client."""
    manager = AuthorizationManager(auth_dir=temp_auth_dir)

    record1 = manager.create_authorization(
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100"]
    )

    record2 = manager.create_authorization(
        operator_id="operator2@example.com",
        client_id="client-001",
        targets=["192.168.1.200"]
    )

    record3 = manager.create_authorization(
        operator_id="operator@example.com",
        client_id="client-002",
        targets=["192.168.1.300"]
    )

    client_records = manager.get_authorizations_by_client("client-001")

    assert len(client_records) == 2
    assert record1.auth_id in [r.auth_id for r in client_records]
    assert record2.auth_id in [r.auth_id for r in client_records]
    assert record3.auth_id not in [r.auth_id for r in client_records]


def test_authorization_manager_cleanup_expired(temp_auth_dir):
    """Test cleaning up expired authorizations."""
    manager = AuthorizationManager(auth_dir=temp_auth_dir)

    # Create expired authorization
    expired_record = manager.create_authorization(
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100"],
        expires_in_days=-1  # Already expired
    )
    manager.approve_authorization(expired_record.auth_id, "admin")

    # Create valid authorization
    valid_record = manager.create_authorization(
        operator_id="operator@example.com",
        client_id="client-002",
        targets=["192.168.1.200"],
        expires_in_days=1
    )
    manager.approve_authorization(valid_record.auth_id, "admin")

    # Cleanup
    removed = manager.cleanup_expired()

    assert removed == 1
    assert manager._records[expired_record.auth_id].status == AuthStatus.EXPIRED
    assert manager._records[valid_record.auth_id].status == AuthStatus.APPROVED


def test_authorization_manager_persistence(temp_auth_dir):
    """Test that authorizations persist across manager instances."""
    # Create first manager and add authorization
    manager1 = AuthorizationManager(auth_dir=temp_auth_dir)
    record = manager1.create_authorization(
        operator_id="operator@example.com",
        client_id="client-001",
        targets=["192.168.1.100"]
    )
    manager1.approve_authorization(record.auth_id, "admin")

    # Create second manager with same directory
    manager2 = AuthorizationManager(auth_dir=temp_auth_dir)

    # Authorization should be loaded
    loaded_record = manager2.get_authorization(record.auth_id)
    assert loaded_record is not None
    assert loaded_record.auth_id == record.auth_id
    assert loaded_record.status == AuthStatus.APPROVED
    assert loaded_record.approved_by == "admin"
