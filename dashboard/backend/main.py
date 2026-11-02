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
    UserRole
)


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


def get_current_user(credentials: HTTPAuthorizationCredentials) -> Optional[Dict[str, Any]]:
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
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Logout and invalidate session."""
    if credentials:
        revoke_session(credentials.credentials)
    
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
    
    assessments[assessment.assessment_id] = {
        **assessment.dict(),
        "created_by": current_user["username"],
        "created_at": datetime.now(UTC).isoformat()
    }
    
    return {"message": "Assessment created", "assessment_id": assessment.assessment_id}


@app.get("/assessments/{assessment_id}")
async def get_assessment(
    assessment_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get a specific assessment."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    assessment = assessments.get(assessment_id)
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
    
    if assessment_id not in assessments:
        raise HTTPException(status_code=404, detail="Assessment not found")
    
    del assessments[assessment_id]
    
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
    
    return {"assessments": list(assessments.values())}


@app.get("/assessments/{assessment_id}/findings")
async def get_findings(
    assessment_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get findings for an assessment."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    if assessment_id not in assessments:
        raise HTTPException(status_code=404, detail="Assessment not found")

    # Placeholder - would load from actual assessment data
    return {"assessment_id": assessment_id, "findings": []}


@app.get("/vulnerabilities")
async def list_vulnerabilities(
    severity: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List vulnerabilities."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Placeholder - would query vulnerability database
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
    
    return {
        "total_assessments": len(assessments),
        "active_assessments": len([a for a in assessments.values() if a["status"] == "running"]),
        "completed_assessments": len([a for a in assessments.values() if a["status"] == "completed"]),
        "total_findings": sum(a.get("findings_count", 0) for a in assessments.values())
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
