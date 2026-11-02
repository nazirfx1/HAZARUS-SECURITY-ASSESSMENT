"""
HAZARUS Dashboard Backend
FastAPI backend for web dashboard.
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging
import json
from pathlib import Path


app = FastAPI(
    title="HAZARUS Dashboard API",
    description="REST API for HAZARUS Security Assessment Framework",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer(auto_error=False)

# Logger
logger = logging.getLogger("hazarus.dashboard")


# Data directory
data_dir = Path.home() / ".hazarus" / "dashboard"
data_dir.mkdir(parents=True, exist_ok=True)


# Models
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


# In-memory storage (in production, use database)
assessments: Dict[str, Dict[str, Any]] = {}


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "HAZARUS Dashboard API",
        "version": "2.0.0",
        "status": "running"
    }


@app.get("/assessments")
async def list_assessments(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """List all assessments."""
    # In production, validate credentials
    return {"assessments": list(assessments.values())}


@app.get("/assessments/{assessment_id}")
async def get_assessment(assessment_id: str, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Get assessment details."""
    if assessment_id not in assessments:
        raise HTTPException(status_code=404, detail="Assessment not found")

    return assessments[assessment_id]


@app.post("/assessments")
async def create_assessment(assessment: Assessment, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Create a new assessment."""
    assessments[assessment.assessment_id] = {
        "assessment_id": assessment.assessment_id,
        "target": assessment.target,
        "status": assessment.status,
        "start_time": assessment.start_time or datetime.utcnow().isoformat(),
        "end_time": assessment.end_time,
        "findings_count": assessment.findings_count,
        "created_at": datetime.utcnow().isoformat()
    }

    return {"status": "created", "assessment_id": assessment.assessment_id}


@app.get("/assessments/{assessment_id}/findings")
async def get_findings(assessment_id: str, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Get findings for an assessment."""
    if assessment_id not in assessments:
        raise HTTPException(status_code=404, detail="Assessment not found")

    # Placeholder - would load from actual assessment data
    return {"assessment_id": assessment_id, "findings": []}


@app.get("/vulnerabilities")
async def list_vulnerabilities(
    severity: Optional[str] = None,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
):
    """List vulnerabilities."""
    # Placeholder - would query vulnerability database
    return {"vulnerabilities": []}


@app.get("/scope")
async def get_scope(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Get current scope configuration."""
    scope_file = Path.home() / ".hazarus" / "config" / "scope.yaml"

    if scope_file.exists():
        with open(scope_file, "r") as f:
            return {"scope": f.read()}
    else:
        return {"scope": None}


@app.post("/scope")
async def update_scope(
    scope: Dict[str, Any],
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
):
    """Update scope configuration."""
    # In production, validate and save scope
    return {"status": "updated"}


@app.get("/dashboard/stats")
async def get_dashboard_stats(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Get dashboard statistics."""
    return {
        "total_assessments": len(assessments),
        "active_assessments": len([a for a in assessments.values() if a["status"] == "running"]),
        "completed_assessments": len([a for a in assessments.values() if a["status"] == "completed"]),
        "total_findings": sum(a.get("findings_count", 0) for a in assessments.values())
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
