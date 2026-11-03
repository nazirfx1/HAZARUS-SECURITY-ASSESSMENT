"""
HAZARUS Reconnaissance Persistence Layer
Database and persistence for reconnaissance results.
"""

import asyncio
import logging
import sqlite3
import json
from datetime import datetime, UTC
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path
import hashlib


@dataclass
class AssessmentRecord:
    """Assessment record for database."""
    assessment_id: str
    target: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = "in_progress"  # in_progress, completed, failed
    phases: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AssetRecord:
    """Asset record for database."""
    assessment_id: str
    asset_type: str  # domain, subdomain, ip, nameserver, etc.
    value: str
    confidence: float
    source: str
    discovered_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FindingRecord:
    """Finding record for database."""
    assessment_id: str
    finding_type: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    evidence: str
    discovered_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class ReconPersistence:
    """Persistence layer for reconnaissance results."""

    def __init__(self, db_path: Optional[str] = None):
        """Initialize persistence layer with database."""
        if db_path is None:
            # Default to ~/.hazarus/reconnaissance.db
            home = Path.home()
            hazarus_dir = home / ".hazarus"
            hazarus_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(hazarus_dir / "reconnaissance.db")

        self.db_path = db_path
        self.logger = logging.getLogger("hazarus.recon_persistence")
        self._init_database()

    def _init_database(self) -> None:
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Assessments table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assessments (
                    assessment_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL,
                    phases TEXT,
                    metadata TEXT
                )
            """)

            # Assets table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL,
                    asset_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    source TEXT NOT NULL,
                    discovered_at TEXT NOT NULL,
                    metadata TEXT,
                    FOREIGN KEY (assessment_id) REFERENCES assessments (assessment_id)
                )
            """)

            # Findings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    evidence TEXT,
                    discovered_at TEXT NOT NULL,
                    metadata TEXT,
                    FOREIGN KEY (assessment_id) REFERENCES assessments (assessment_id)
                )
            """)

            # Indexes for performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_assets_assessment
                ON assets (assessment_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_assets_type
                ON assets (asset_type)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_assessment
                ON findings (assessment_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_severity
                ON findings (severity)
            """)

            conn.commit()
            self.logger.info(f"Database initialized: {self.db_path}")

    def generate_assessment_id(self, target: str) -> str:
        """Generate unique assessment ID."""
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        target_hash = hashlib.md5(target.encode()).hexdigest()[:8]
        return f"{timestamp}_{target_hash}"

    async def create_assessment(
        self,
        target: str,
        phases: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create new assessment record."""
        assessment_id = self.generate_assessment_id(target)
        started_at = datetime.now(UTC).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO assessments
                (assessment_id, target, started_at, status, phases, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                assessment_id,
                target,
                started_at,
                "in_progress",
                json.dumps(phases),
                json.dumps(metadata or {})
            ))
            conn.commit()

        self.logger.info(f"Created assessment: {assessment_id}")
        return assessment_id

    async def complete_assessment(self, assessment_id: str) -> None:
        """Mark assessment as completed."""
        completed_at = datetime.now(UTC).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE assessments
                SET completed_at = ?, status = 'completed'
                WHERE assessment_id = ?
            """, (completed_at, assessment_id))
            conn.commit()

        self.logger.info(f"Completed assessment: {assessment_id}")

    async def fail_assessment(self, assessment_id: str, error: str) -> None:
        """Mark assessment as failed."""
        completed_at = datetime.now(UTC).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE assessments
                SET completed_at = ?, status = 'failed'
                WHERE assessment_id = ?
            """, (completed_at, assessment_id))
            conn.commit()

        self.logger.error(f"Failed assessment: {assessment_id} - {error}")

    async def save_asset(self, record: AssetRecord) -> None:
        """Save asset record to database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO assets
                (assessment_id, asset_type, value, confidence, source, discovered_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                record.assessment_id,
                record.asset_type,
                record.value,
                record.confidence,
                record.source,
                record.discovered_at.isoformat(),
                json.dumps(record.metadata)
            ))
            conn.commit()

    async def save_assets(self, records: List[AssetRecord]) -> None:
        """Save multiple asset records."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for record in records:
                cursor.execute("""
                    INSERT INTO assets
                    (assessment_id, asset_type, value, confidence, source, discovered_at, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.assessment_id,
                    record.asset_type,
                    record.value,
                    record.confidence,
                    record.source,
                    record.discovered_at.isoformat(),
                    json.dumps(record.metadata)
                ))
            conn.commit()

    async def save_finding(self, record: FindingRecord) -> None:
        """Save finding record to database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO findings
                (assessment_id, finding_type, severity, title, description, evidence, discovered_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.assessment_id,
                record.finding_type,
                record.severity,
                record.title,
                record.description,
                record.evidence,
                record.discovered_at.isoformat(),
                json.dumps(record.metadata)
            ))
            conn.commit()

    async def load_assessment(self, assessment_id: str) -> Optional[AssessmentRecord]:
        """Load assessment record."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT assessment_id, target, started_at, completed_at, status, phases, metadata
                FROM assessments
                WHERE assessment_id = ?
            """, (assessment_id,))

            row = cursor.fetchone()
            if row:
                return AssessmentRecord(
                    assessment_id=row[0],
                    target=row[1],
                    started_at=datetime.fromisoformat(row[2]),
                    completed_at=datetime.fromisoformat(row[3]) if row[3] else None,
                    status=row[4],
                    phases=json.loads(row[5]),
                    metadata=json.loads(row[6])
                )
        return None

    async def load_assets(self, assessment_id: str) -> List[AssetRecord]:
        """Load all assets for assessment."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT asset_type, value, confidence, source, discovered_at, metadata
                FROM assets
                WHERE assessment_id = ?
            """, (assessment_id,))

            assets = []
            for row in cursor.fetchall():
                assets.append(AssetRecord(
                    assessment_id=assessment_id,
                    asset_type=row[0],
                    value=row[1],
                    confidence=row[2],
                    source=row[3],
                    discovered_at=datetime.fromisoformat(row[4]),
                    metadata=json.loads(row[5])
                ))

        return assets

    async def load_findings(self, assessment_id: str) -> List[FindingRecord]:
        """Load all findings for assessment."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT finding_type, severity, title, description, evidence, discovered_at, metadata
                FROM findings
                WHERE assessment_id = ?
            """, (assessment_id,))

            findings = []
            for row in cursor.fetchall():
                findings.append(FindingRecord(
                    assessment_id=assessment_id,
                    finding_type=row[0],
                    severity=row[1],
                    title=row[2],
                    description=row[3],
                    evidence=row[4],
                    discovered_at=datetime.fromisoformat(row[5]),
                    metadata=json.loads(row[6])
                ))

        return findings

    async def compare_assessments(
        self,
        old_id: str,
        new_id: str
    ) -> Dict[str, Any]:
        """Compare two assessments and detect changes."""
        old_assets = await self.load_assets(old_id)
        new_assets = await self.load_assets(new_id)

        old_values = {a.value for a in old_assets}
        new_values = {a.value for a in new_assets}

        added = new_values - old_values
        removed = old_values - new_values
        unchanged = old_values & new_values

        return {
            "old_assessment": old_id,
            "new_assessment": new_id,
            "added_assets": list(added),
            "removed_assets": list(removed),
            "unchanged_assets": list(unchanged),
            "added_count": len(added),
            "removed_count": len(removed),
            "unchanged_count": len(unchanged)
        }

    async def export_results(
        self,
        assessment_id: str,
        format: str = "json"
    ) -> str:
        """Export assessment results."""
        assessment = await self.load_assessment(assessment_id)
        assets = await self.load_assets(assessment_id)
        findings = await self.load_findings(assessment_id)

        if format == "json":
            result = {
                "assessment": asdict(assessment),
                "assets": [asdict(a) for a in assets],
                "findings": [asdict(f) for f in findings]
            }
            return json.dumps(result, indent=2, default=str)

        elif format == "csv":
            import csv
            import io

            output = io.StringIO()
            writer = csv.writer(output)

            # Write assets
            writer.writerow(["Asset Type", "Value", "Confidence", "Source", "Discovered At"])
            for asset in assets:
                writer.writerow([
                    asset.asset_type,
                    asset.value,
                    asset.confidence,
                    asset.source,
                    asset.discovered_at.isoformat()
                ])

            # Write findings
            writer.writerow([])
            writer.writerow(["Finding Type", "Severity", "Title", "Description", "Evidence"])
            for finding in findings:
                writer.writerow([
                    finding.finding_type,
                    finding.severity,
                    finding.title,
                    finding.description,
                    finding.evidence
                ])

            return output.getvalue()

        else:
            raise ValueError(f"Unsupported format: {format}")

    async def get_recent_assessments(self, limit: int = 10) -> List[AssessmentRecord]:
        """Get recent assessments."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT assessment_id, target, started_at, completed_at, status, phases, metadata
                FROM assessments
                ORDER BY started_at DESC
                LIMIT ?
            """, (limit,))

            assessments = []
            for row in cursor.fetchall():
                assessments.append(AssessmentRecord(
                    assessment_id=row[0],
                    target=row[1],
                    started_at=datetime.fromisoformat(row[2]),
                    completed_at=datetime.fromisoformat(row[3]) if row[3] else None,
                    status=row[4],
                    phases=json.loads(row[5]),
                    metadata=json.loads(row[6])
                ))

        return assessments
