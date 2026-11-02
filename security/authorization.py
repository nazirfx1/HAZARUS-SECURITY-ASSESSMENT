"""
HAZARUS Authorization Manager
Manages operator and client authorization records.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import logging
from pathlib import Path
import json
import hashlib


class AuthStatus(Enum):
    """Authorization status."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class AuthorizationRecord:
    """Authorization record for an assessment."""
    auth_id: str
    operator_id: str
    client_id: str
    targets: List[str]
    status: AuthStatus = AuthStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    approved_at: Optional[datetime] = None
    approved_by: Optional[str] = None
    expires_at: Optional[datetime] = None
    notes: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_valid(self) -> bool:
        """Check if authorization is currently valid."""
        if self.status != AuthStatus.APPROVED:
            return False

        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False

        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "auth_id": self.auth_id,
            "operator_id": self.operator_id,
            "client_id": self.client_id,
            "targets": self.targets,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "approved_by": self.approved_by,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "notes": self.notes,
            "metadata": self.metadata
        }


class AuthorizationManager:
    """
    Manages authorization records and validates operator permissions.
    """

    def __init__(self, auth_dir: Optional[Path] = None):
        self.logger = logging.getLogger("hazarus.authorization_manager")

        if auth_dir is None:
            auth_dir = Path.home() / ".hazarus" / "authorization"

        self.auth_dir = auth_dir
        self.auth_dir.mkdir(parents=True, exist_ok=True)

        self._records: Dict[str, AuthorizationRecord] = {}
        self._load_records()

    def _load_records(self) -> None:
        """Load authorization records from disk."""
        for auth_file in self.auth_dir.glob("*.json"):
            try:
                with open(auth_file, "r") as f:
                    data = json.load(f)

                # Convert status string to enum
                data["status"] = AuthStatus(data["status"])
                data["created_at"] = datetime.fromisoformat(data["created_at"])
                if data.get("approved_at"):
                    data["approved_at"] = datetime.fromisoformat(data["approved_at"])
                if data.get("expires_at"):
                    data["expires_at"] = datetime.fromisoformat(data["expires_at"])

                record = AuthorizationRecord(**data)
                self._records[record.auth_id] = record

            except Exception as e:
                self.logger.error(f"Failed to load auth record {auth_file}: {e}")

    def _save_record(self, record: AuthorizationRecord) -> bool:
        """Save authorization record to disk."""
        try:
            auth_file = self.auth_dir / f"{record.auth_id}.json"
            with open(auth_file, "w") as f:
                json.dump(record.to_dict(), f, indent=2)
            return True
        except Exception as e:
            self.logger.error(f"Failed to save auth record: {e}")
            return False

    def create_authorization(
        self,
        operator_id: str,
        client_id: str,
        targets: List[str],
        expires_in_days: Optional[int] = None,
        notes: str = ""
    ) -> AuthorizationRecord:
        """Create a new authorization request."""
        auth_id = self._generate_auth_id(operator_id, client_id)

        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + datetime.timedelta(days=expires_in_days)

        record = AuthorizationRecord(
            auth_id=auth_id,
            operator_id=operator_id,
            client_id=client_id,
            targets=targets,
            expires_at=expires_at,
            notes=notes
        )

        self._records[auth_id] = record
        self._save_record(record)

        self.logger.info(f"Created authorization request: {auth_id}")
        return record

    def _generate_auth_id(self, operator_id: str, client_id: str) -> str:
        """Generate a unique authorization ID."""
        timestamp = datetime.utcnow().isoformat()
        data = f"{operator_id}:{client_id}:{timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def approve_authorization(self, auth_id: str, approved_by: str) -> bool:
        """Approve an authorization request."""
        if auth_id not in self._records:
            return False

        record = self._records[auth_id]
        record.status = AuthStatus.APPROVED
        record.approved_at = datetime.utcnow()
        record.approved_by = approved_by

        self._save_record(record)
        self.logger.info(f"Approved authorization: {auth_id} by {approved_by}")
        return True

    def deny_authorization(self, auth_id: str, reason: str = "") -> bool:
        """Deny an authorization request."""
        if auth_id not in self._records:
            return False

        record = self._records[auth_id]
        record.status = AuthStatus.DENIED
        record.notes = reason

        self._save_record(record)
        self.logger.info(f"Denied authorization: {auth_id}")
        return True

    def revoke_authorization(self, auth_id: str) -> bool:
        """Revoke an authorization."""
        if auth_id not in self._records:
            return False

        record = self._records[auth_id]
        record.status = AuthStatus.REVOKED

        self._save_record(record)
        self.logger.warning(f"Revoked authorization: {auth_id}")
        return True

    def validate_authorization(self, auth_id: str) -> bool:
        """Validate that an authorization is currently valid."""
        if auth_id not in self._records:
            return False

        return self._records[auth_id].is_valid()

    def get_authorization(self, auth_id: str) -> Optional[AuthorizationRecord]:
        """Get an authorization record."""
        return self._records.get(auth_id)

    def get_authorizations_by_operator(self, operator_id: str) -> List[AuthorizationRecord]:
        """Get all authorizations for an operator."""
        return [r for r in self._records.values() if r.operator_id == operator_id]

    def get_authorizations_by_client(self, client_id: str) -> List[AuthorizationRecord]:
        """Get all authorizations for a client."""
        return [r for r in self._records.values() if r.client_id == client_id]

    def cleanup_expired(self) -> int:
        """Remove expired authorization records."""
        removed = 0
        now = datetime.utcnow()

        for auth_id, record in list(self._records.items()):
            if record.expires_at and now > record.expires_at:
                record.status = AuthStatus.EXPIRED
                self._save_record(record)
                removed += 1

        if removed > 0:
            self.logger.info(f"Cleaned up {removed} expired authorizations")

        return removed
