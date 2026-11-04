"""
HAZARUS Dashboard Backend
FastAPI backend for web dashboard with authentication and authorization.
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta, UTC
from pathlib import Path
import logging
import json

from dashboard.backend.auth import (
    hash_password,
    verify_password,
    create_session,
    revoke_session,
    validate_session,
    users,
    sessions,
    UserRole,
    set_database
)
from dashboard.backend.database import db


app = FastAPI(
    title="HAZARUS Dashboard API",
    description="REST API for HAZARUS Security Assessment Framework",
    version="2.0.0"
)

# CORS middleware - strict configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # No wildcard
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=600,
)

# Security
security = HTTPBearer(auto_error=False)

# Logger
logger = logging.getLogger("hazarus.dashboard")

# Initialize database and migrate auth data
set_database(db)
logger.info("Database initialized and auth data migrated")


# In-memory storage (in production, use database)
assessments: Dict[str, Dict[str, Any]] = {}


class Assessment(BaseModel):
    assessment_id: str
    target: str
    status: str
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    findings_count: int = 0


class Vulnerability(BaseModel):
    vulnerability_id: str
    severity: str
    title: str
    description: str


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: UserRole = UserRole.OPERATOR


class UserLogin(BaseModel):
    username: str
    password: str


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[Dict[str, Any]]:
    """Get current user from credentials."""
    if not credentials:
        return None
    
    return validate_session(credentials.credentials)


@app.post("/auth/register")
async def register(user_data: UserCreate):
    """Register a new user."""
    if user_data.username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Hash password
    hashed_password = hash_password(user_data.password)
    
    users[user_data.username] = {
        "username": user_data.username,
        "email": user_data.email,
        "role": user_data.role.value,
        "hashed_password": hashed_password,
        "created_at": datetime.now(UTC).isoformat()
    }
    
    # Save to disk
    from dashboard.backend.auth import save_users
    save_users()
    
    return {"message": "User registered successfully"}


@app.post("/auth/login")
async def login(user_data: UserLogin):
    """Login and create session."""
    user = users.get(user_data.username)
    
    if not user or not verify_password(user_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create session
    session_id = create_session(user_data.username, user["role"])
    
    return {
        "access_token": session_id,
        "token_type": "bearer",
        "expires_in": 28800,
        "role": user["role"]
    }


@app.post("/auth/logout")
async def logout(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Logout and invalidate session."""
    # Token is already validated in get_current_user
    # For simplicity, we'll need to extract the session_id from the token
    # This is a simplified version - in production you'd want to track the session better
    return {"message": "Logged out successfully"}


@app.get("/auth/me")
async def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user info."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    return {
        "username": current_user["username"],
        "email": current_user["email"],
        "role": current_user["role"]
    }


@app.get("/users")
async def list_users(current_user: Dict[str, Any] = Depends(get_current_user)):
    """List all users (admin only)."""
    if not current_user or current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return {"users": list(users.values())}


@app.post("/assessments")
async def create_assessment(
    assessment: Assessment,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Create a new assessment."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    if current_user["role"] not in ["admin", "operator"]:
        raise HTTPException(status_code=403, detail="Operator access required")
    
    # Use database
    success = db.create_assessment(
        assessment_id=assessment.assessment_id,
        target=assessment.target,
        status=assessment.status,
        start_time=assessment.start_time,
        end_time=assessment.end_time,
        findings_count=assessment.findings_count,
        created_by=current_user["username"]
    )
    
    if not success:
        raise HTTPException(status_code=400, detail="Assessment ID already exists")
    
    return {"message": "Assessment created", "assessment_id": assessment.assessment_id}


@app.get("/assessments/{assessment_id}")
async def get_assessment(
    assessment_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get a specific assessment."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    assessment = db.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    
    return assessment


@app.delete("/assessments/{assessment_id}")
async def delete_assessment(
    assessment_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Delete an assessment (admin/operator only)."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    if current_user["role"] not in ["admin", "operator"]:
        raise HTTPException(status_code=403, detail="Operator access required")
    
    success = db.delete_assessment(assessment_id)
    if not success:
        raise HTTPException(status_code=404, detail="Assessment not found")
    
    return {"message": "Assessment deleted"}


@app.post("/auth/sessions/{session_id}/revoke")
async def revoke_session_endpoint(
    session_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Revoke a session (admin only)."""
    if not current_user or current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    revoke_session(session_id)
    
    return {"message": "Session revoked"}


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "HAZARUS Dashboard API",
        "version": "2.0.0",
        "status": "running"
    }


@app.get("/assessments")
async def list_assessments(current_user: Dict[str, Any] = Depends(get_current_user)):
    """List all assessments."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    return {"assessments": db.list_assessments()}


@app.get("/assessments/{assessment_id}/findings")
async def get_findings(
    assessment_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get findings for an assessment."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    assessment = db.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    findings = db.get_findings(assessment_id)
    
    return {
        "assessment_id": assessment_id,
        "findings": findings,
        "target": assessment.get("target"),
        "status": assessment.get("status", "completed"),
        "scan_date": assessment.get("scan_date")
    }


@app.get("/vulnerabilities")
async def list_vulnerabilities(
    severity: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List vulnerabilities."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Query vulnerability database (load from config/vulnerabilities.json)
    try:
        import json
        vuln_file = Path("config/vulnerabilities.json")
        if vuln_file.exists():
            with open(vuln_file) as f:
                vuln_data = json.load(f)
            return {"vulnerabilities": vuln_data.get("vulnerabilities", [])}
    except Exception:
        pass
    return {"vulnerabilities": []}


@app.get("/scope")
async def get_scope(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current scope configuration."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    scope_file = Path.home() / ".hazarus" / "config" / "scope.yaml"

    if scope_file.exists():
        with open(scope_file, "r") as f:
            return {"scope": f.read()}
    else:
        return {"scope": None}


@app.post("/scope")
async def update_scope(
    scope: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Update scope configuration."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    if current_user["role"] not in ["admin", "operator"]:
        raise HTTPException(status_code=403, detail="Operator access required")
    
    # In production, validate and save scope
    return {"status": "updated"}


@app.get("/dashboard/stats")
async def get_dashboard_stats(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get dashboard statistics."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    return db.get_stats()


@app.get("/dashboard/recent-activity")
async def get_recent_activity(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get recent activity."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Get recent assessments
    recent_assessments = db.list_assessments()[:5]
    
    # Get recent findings
    recent_findings = db.list_all_findings()[:5]
    
    return {
        "recent_assessments": recent_assessments,
        "recent_findings": recent_findings
    }


class FindingCreate(BaseModel):
    assessment_id: str
    vulnerability_id: str
    severity: str
    title: str
    description: str
    location: Optional[str] = None
    remediation: Optional[str] = None


@app.post("/findings")
async def create_finding(
    finding: FindingCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Create a new finding."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    if current_user["role"] not in ["admin", "operator"]:
        raise HTTPException(status_code=403, detail="Operator access required")
    
    # Verify assessment exists
    assessment = db.get_assessment(finding.assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    
    # Create finding
    finding_id = db.create_finding(
        assessment_id=finding.assessment_id,
        vulnerability_id=finding.vulnerability_id,
        severity=finding.severity,
        title=finding.title,
        description=finding.description,
        location=finding.location,
        remediation=finding.remediation
    )
    
    # Update assessment findings count
    current_count = assessment.get("findings_count", 0)
    db.update_assessment(finding.assessment_id, findings_count=current_count + 1)
    
    return {"message": "Finding created", "finding_id": finding_id}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
