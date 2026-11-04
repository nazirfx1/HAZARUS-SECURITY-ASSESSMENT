"""
HAZARUS Dashboard Database
SQLite database for persistent storage of assessments, findings, and users.
"""

import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, UTC
import json
import logging

logger = logging.getLogger("hazarus.dashboard")


class Database:
    """SQLite database manager for HAZARUS dashboard."""
    
    def __init__(self, db_path: Optional[Path] = None):
        """Initialize database connection."""
        if db_path is None:
            # Default to ~/.hazarus/dashboard.db
            db_path = Path.home() / ".hazarus" / "dashboard.db"
        
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_db(self):
        """Initialize database schema."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                hashed_password TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        
        # Assessments table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                assessment_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                start_time TEXT,
                end_time TEXT,
                findings_count INTEGER DEFAULT 0,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                scan_date TEXT,
                FOREIGN KEY (created_by) REFERENCES users(username)
            )
        """)
        
        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id TEXT NOT NULL,
                vulnerability_id TEXT,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                location TEXT,
                remediation TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
            )
        """)
        
        # Sessions table (for session management)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {self.db_path}")
    
    # User operations
    def create_user(self, username: str, email: str, hashed_password: str, role: str) -> bool:
        """Create a new user."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, email, role, hashed_password, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, email, role, hashed_password, datetime.now(UTC).isoformat())
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
    
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
    def list_users(self) -> List[Dict[str, Any]]:
        """List all users."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    # Assessment operations
    def create_assessment(self, assessment_id: str, target: str, status: str, 
                          start_time: Optional[str], end_time: Optional[str],
                          findings_count: int, created_by: str) -> bool:
        """Create a new assessment."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO assessments 
                   (assessment_id, target, status, start_time, end_time, findings_count, created_by, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (assessment_id, target, status, start_time, end_time, findings_count, 
                 created_by, datetime.now(UTC).isoformat())
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
    
    def get_assessment(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        """Get assessment by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM assessments WHERE assessment_id = ?", (assessment_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
    def list_assessments(self) -> List[Dict[str, Any]]:
        """List all assessments."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM assessments ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def update_assessment(self, assessment_id: str, **kwargs) -> bool:
        """Update assessment fields."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        valid_fields = {'target', 'status', 'start_time', 'end_time', 'findings_count', 'scan_date'}
        updates = {k: v for k, v in kwargs.items() if k in valid_fields}
        
        if not updates:
            conn.close()
            return False
        
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [assessment_id]
        
        cursor.execute(
            f"UPDATE assessments SET {set_clause} WHERE assessment_id = ?",
            values
        )
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success
    
    def delete_assessment(self, assessment_id: str) -> bool:
        """Delete an assessment."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM assessments WHERE assessment_id = ?", (assessment_id,))
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success
    
    # Finding operations
    def create_finding(self, assessment_id: str, vulnerability_id: str, severity: str,
                       title: str, description: str, location: Optional[str] = None,
                       remediation: Optional[str] = None) -> int:
        """Create a new finding."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO findings 
               (assessment_id, vulnerability_id, severity, title, description, location, remediation, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (assessment_id, vulnerability_id, severity, title, description, location, 
             remediation, datetime.now(UTC).isoformat())
        )
        finding_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return finding_id
    
    def get_findings(self, assessment_id: str) -> List[Dict[str, Any]]:
        """Get all findings for an assessment."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE assessment_id = ?", (assessment_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def list_all_findings(self) -> List[Dict[str, Any]]:
        """List all findings across all assessments."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    # Session operations
    def create_session(self, session_id: str, username: str, role: str, 
                       expires_at: str) -> bool:
        """Create a new session."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO sessions (session_id, username, role, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (session_id, username, role, datetime.now(UTC).isoformat(), expires_at)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success
    
    def cleanup_expired_sessions(self) -> int:
        """Delete expired sessions."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.now(UTC).isoformat(),))
        conn.commit()
        deleted = cursor.rowcount
        conn.close()
        return deleted
    
    # Statistics
    def get_stats(self) -> Dict[str, int]:
        """Get dashboard statistics."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM assessments")
        total = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM assessments WHERE status = 'running'")
        active = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM assessments WHERE status = 'completed'")
        completed = cursor.fetchone()[0]
        
        cursor.execute("SELECT SUM(findings_count) FROM assessments")
        total_findings = cursor.fetchone()[0] or 0
        
        conn.close()
        return {
            "total_assessments": total,
            "active_assessments": active,
            "completed_assessments": completed,
            "total_findings": total_findings
        }


# Global database instance
db = Database()
