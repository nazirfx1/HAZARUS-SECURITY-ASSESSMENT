"""
HAZARUS Dashboard Authentication Module
Argon2id password hashing and session management.
"""

from enum import Enum
from typing import Dict, Any, Optional
from datetime import datetime, timedelta, UTC
from pathlib import Path
import secrets
import json
from argon2 import PasswordHasher


class UserRole(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


# Data directory
data_dir = Path.home() / ".hazarus" / "dashboard"
data_dir.mkdir(parents=True, exist_ok=True)
users_db = data_dir / "users.json"
sessions_db = data_dir / "sessions.json"

# Password hasher (Argon2id)
pwd_hasher = PasswordHasher(
    time_cost=3,  # Memory tradeoff
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)


# Storage
users: Dict[str, Dict[str, Any]] = {}
sessions: Dict[str, Dict[str, Any]] = {}


def load_users():
    """Load users from disk."""
    if users_db.exists():
        with open(users_db, "r") as f:
            return json.load(f)
    return {}


def save_users():
    """Save users to disk."""
    with open(users_db, "w") as f:
        json.dump(users, f, indent=2)


def load_sessions():
    """Load sessions from disk."""
    if sessions_db.exists():
        with open(sessions_db, "r") as f:
            return json.load(f)
    return {}


def save_sessions():
    """Save sessions to disk."""
    with open(sessions_db, "w") as f:
        json.dump(sessions, f, indent=2)


# Initialize data
users = load_users()
sessions = load_sessions()


def hash_password(password: str) -> str:
    """Hash password with Argon2id."""
    return pwd_hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash."""
    try:
        return pwd_hasher.verify(hashed, password)
    except:
        return False


def create_session(username: str, role: str) -> str:
    """Create a new session."""
    session_id = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(hours=8)
    
    sessions[session_id] = {
        "session_id": session_id,
        "username": username,
        "created_at": datetime.now(UTC).isoformat(),
        "expires_at": expires_at.isoformat(),
        "role": role
    }
    
    save_sessions()
    
    return session_id


def revoke_session(session_id: str) -> bool:
    """Revoke a session."""
    if session_id in sessions:
        del sessions[session_id]
        save_sessions()
        return True
    return False


def validate_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Validate a session and return user info."""
    session = sessions.get(session_id)
    
    if not session:
        return None
    
    # Check expiration
    if datetime.now(UTC) > datetime.fromisoformat(session["expires_at"]):
        del sessions[session_id]
        save_sessions()
        return None
    
    return users.get(session["username"])
