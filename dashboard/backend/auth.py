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


# Storage (legacy JSON for backward compatibility)
users: Dict[str, Dict[str, Any]] = {}
sessions: Dict[str, Dict[str, Any]] = {}


def load_users():
    """Load users from disk (legacy)."""
    if users_db.exists():
        with open(users_db, "r") as f:
            return json.load(f)
    return {}


def save_users():
    """Save users to disk (legacy)."""
    with open(users_db, "w") as f:
        json.dump(users, f, indent=2)


def load_sessions():
    """Load sessions from disk (legacy)."""
    if sessions_db.exists():
        with open(sessions_db, "r") as f:
            return json.load(f)
    return {}


def save_sessions():
    """Save sessions to disk (legacy)."""
    with open(sessions_db, "w") as f:
        json.dump(sessions, f, indent=2)


# Initialize data (load from legacy JSON if exists)
users = load_users()
sessions = load_sessions()

# Database instance (will be used by main.py)
_database = None


def set_database(database):
    """Set the database instance for auth operations."""
    global _database
    _database = database
    
    # Migrate legacy data to database if it exists
    if users:
        for username, user_data in users.items():
            _database.create_user(
                username=username,
                email=user_data.get("email", ""),
                hashed_password=user_data.get("hashed_password", ""),
                role=user_data.get("role", "viewer")
            )
        # Clear legacy after migration
        users.clear()
        save_users()


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
    
    # Use database if available
    if _database:
        _database.create_session(session_id, username, role, expires_at.isoformat())
    else:
        # Legacy fallback
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
    if _database:
        return _database.delete_session(session_id)
    else:
        # Legacy fallback
        if session_id in sessions:
            del sessions[session_id]
            save_sessions()
            return True
        return False


def validate_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Validate a session and return user info."""
    session = None
    username = None
    
    if _database:
        session = _database.get_session(session_id)
        if session:
            username = session["username"]
    else:
        # Legacy fallback
        session = sessions.get(session_id)
        if session:
            username = session["username"]
    
    if not session:
        return None
    
    # Check expiration
    if datetime.now(UTC) > datetime.fromisoformat(session["expires_at"]):
        if _database:
            _database.delete_session(session_id)
        else:
            del sessions[session_id]
            save_sessions()
        return None
    
    # Get user info
    if _database:
        user = _database.get_user(username)
        if user:
            return {
                "username": user["username"],
                "email": user["email"],
                "role": user["role"]
            }
    else:
        # Legacy fallback
        return users.get(username)
    
    return None
