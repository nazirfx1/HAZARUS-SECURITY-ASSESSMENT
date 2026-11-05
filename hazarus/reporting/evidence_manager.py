"""
HAZARUS Evidence Manager
Evidence collection and management.
"""

import logging
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import base64


@dataclass
class Evidence:
    """Evidence item."""
    evidence_id: str
    type: str  # screenshot, log, output, config
    description: str
    collected_at: datetime
    data: Optional[str] = None
    file_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class EvidenceManager:
    """Evidence management module."""

    def __init__(self, assessment_id: str, evidence_dir: Optional[Path] = None):
        self.assessment_id = assessment_id
        self.logger = logging.getLogger("hazarus.evidence_manager")

        if evidence_dir is None:
            evidence_dir = Path.home() / ".hazarus" / "evidence" / assessment_id

        self.evidence_dir = evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        self._evidence: Dict[str, Evidence] = {}
        self._load_evidence_index()

    def _load_evidence_index(self) -> None:
        """Load evidence index from disk."""
        index_file = self.evidence_dir / "index.json"

        if index_file.exists():
            try:
                with open(index_file, "r") as f:
                    data = json.load(f)

                for evidence_id, evidence_data in data.items():
                    self._evidence[evidence_id] = Evidence(
                        evidence_id=evidence_id,
                        type=evidence_data["type"],
                        description=evidence_data["description"],
                        collected_at=datetime.fromisoformat(evidence_data["collected_at"]),
                        data=evidence_data.get("data"),
                        file_path=evidence_data.get("file_path"),
                        metadata=evidence_data.get("metadata", {})
                    )

            except Exception as e:
                self.logger.error(f"Failed to load evidence index: {e}")

    def _save_evidence_index(self) -> None:
        """Save evidence index to disk."""
        index_file = self.evidence_dir / "index.json"

        try:
            data = {}
            for evidence_id, evidence in self._evidence.items():
                data[evidence_id] = {
                    "type": evidence.type,
                    "description": evidence.description,
                    "collected_at": evidence.collected_at.isoformat(),
                    "data": evidence.data,
                    "file_path": evidence.file_path,
                    "metadata": evidence.metadata
                }

            with open(index_file, "w") as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            self.logger.error(f"Failed to save evidence index: {e}")

    async def collect(self, evidence_type: str, data: Dict[str, Any]) -> Evidence:
        """Collect evidence."""
        import uuid

        evidence_id = str(uuid.uuid4())[:8]

        evidence = Evidence(
            evidence_id=evidence_id,
            type=evidence_type,
            description=data.get("description", ""),
            collected_at=datetime.utcnow(),
            data=json.dumps(data.get("data", {})),
            metadata=data.get("metadata", {})
        )

        # Save to file if large data
        if evidence.data and len(evidence.data) > 10000:
            file_path = self.evidence_dir / f"{evidence_id}.json"
            with open(file_path, "w") as f:
                f.write(evidence.data)
            evidence.file_path = str(file_path)
            evidence.data = None

        self._evidence[evidence_id] = evidence
        self._save_evidence_index()

        self.logger.info(f"Collected evidence: {evidence_id}")
        return evidence

    async def collect_file(self, evidence_type: str, file_path: Path, description: str) -> Evidence:
        """Collect a file as evidence."""
        import uuid
        import shutil

        evidence_id = str(uuid.uuid4())[:8]

        # Copy file to evidence directory
        dest_path = self.evidence_dir / f"{evidence_id}_{file_path.name}"
        shutil.copy(file_path, dest_path)

        evidence = Evidence(
            evidence_id=evidence_id,
            type=evidence_type,
            description=description,
            collected_at=datetime.utcnow(),
            file_path=str(dest_path),
            metadata={"original_path": str(file_path)}
        )

        self._evidence[evidence_id] = evidence
        self._save_evidence_index()

        self.logger.info(f"Collected file evidence: {evidence_id}")
        return evidence

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        """Get evidence by ID."""
        return self._evidence.get(evidence_id)

    def list_evidence(self, evidence_type: Optional[str] = None) -> List[Evidence]:
        """List all evidence, optionally filtered by type."""
        evidence = list(self._evidence.values())

        if evidence_type:
            evidence = [e for e in evidence if e.type == evidence_type]

        return evidence

    def to_dict(self, evidence: Evidence) -> Dict[str, Any]:
        """Convert evidence to dictionary."""
        return {
            "evidence_id": evidence.evidence_id,
            "type": evidence.type,
            "description": evidence.description,
            "collected_at": evidence.collected_at.isoformat(),
            "file_path": evidence.file_path,
            "metadata": evidence.metadata
        }
