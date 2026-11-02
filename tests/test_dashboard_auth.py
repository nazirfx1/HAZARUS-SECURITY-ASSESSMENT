"""
HAZARUS Dashboard Authentication Tests
Tests for dashboard authentication, authorization, and session management.
"""

import pytest
from datetime import datetime, UTC
from dashboard.backend.auth import (
    hash_password,
    verify_password,
    UserRole,
    create_session,
    revoke_session,
    validate_session,
    users,
    sessions
)


def test_password_hashing():
    """Test Argon2id password hashing."""
    password = "TestPassword123!"
    hashed = hash_password(password)
    
    assert hashed != password
    assert len(hashed) > 50


def test_password_verification():
    """Test password verification."""
    password = "TestPassword123!"
    hashed = hash_password(password)
    
    # Correct password
    assert verify_password(password, hashed) == True
    
    # Wrong password
    assert verify_password("WrongPassword123!", hashed) == False


def test_user_role_enum():
    """Test user role enumeration."""
    assert UserRole.ADMIN.value == "admin"
    assert UserRole.OPERATOR.value == "operator"
    assert UserRole.VIEWER.value == "viewer"


def test_session_creation():
    """Test session creation."""
    # Add test user
    users["testuser"] = {
        "username": "testuser",
        "email": "test@example.com",
        "role": "operator",
        "hashed_password": hash_password("TestPassword123!"),
        "created_at": datetime.now(UTC).isoformat()
    }
    
    session_id = create_session("testuser", "operator")
    
    assert session_id in sessions
    assert sessions[session_id]["username"] == "testuser"
    assert sessions[session_id]["role"] == "operator"
    
    # Cleanup
    del users["testuser"]
    del sessions[session_id]


def test_session_validation():
    """Test session validation."""
    # Add test user
    users["testuser"] = {
        "username": "testuser",
        "email": "test@example.com",
        "role": "operator",
        "hashed_password": hash_password("TestPassword123!"),
        "created_at": datetime.now(UTC).isoformat()
    }
    
    session_id = create_session("testuser", "operator")
    
    # Valid session
    user = validate_session(session_id)
    assert user is not None
    assert user["username"] == "testuser"
    
    # Cleanup
    del users["testuser"]
    del sessions[session_id]


def test_session_revocation():
    """Test session revocation."""
    # Add test user
    users["testuser"] = {
        "username": "testuser",
        "email": "test@example.com",
        "role": "operator",
        "hashed_password": hash_password("TestPassword123!"),
        "created_at": datetime.now(UTC).isoformat()
    }
    
    session_id = create_session("testuser", "operator")
    
    # Revoke session
    result = revoke_session(session_id)
    assert result == True
    assert session_id not in sessions
    
    # Cleanup
    del users["testuser"]


def test_password_hash_uniqueness():
    """Test that same password produces different hashes (salt)."""
    password = "TestPassword123!"
    hash1 = hash_password(password)
    hash2 = hash_password(password)
    
    # Different hashes due to salt
    assert hash1 != hash2
    
    # Both verify correctly
    assert verify_password(password, hash1) == True
    assert verify_password(password, hash2) == True
