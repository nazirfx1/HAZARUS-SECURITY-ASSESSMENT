"""
HAZARUS Bandit Integration
Python security static analysis.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class BanditResult:
    """Bandit scan result."""
    target: str
    total_issues: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0
    issues: List[Dict] = field(default_factory=list)
    scanned_at: datetime = None
    
    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class BanditScanner:
    """Bandit integration for Python SAST."""
    
    def __init__(self):
        self.tool_name = "bandit"
    
    async def scan(self, target: str) -> BanditResult:
        """Scan Python code with Bandit.
        
        Args:
            target: Target file or directory
            
        Returns:
            BanditResult with security issues
        """
        result = BanditResult(target=target)
        
        try:
            # Check if bandit is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "bandit",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("Bandit not installed")
            
            # Get timeout from config
            from core.config import get_config
            config = get_config()
            timeout = config.get('timeouts.code_analysis', 300)
            
            # Build command
            cmd = [
                "bandit",
                "-r", target,
                "-f", "json",
                "-o", "-"
            ]
            
            # Execute
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300
            )
            
            # Parse output
            output = stdout.decode()
            result = self._parse_output(output, target)
            
        except Exception as e:
            print(f"Bandit error: {e}")
        
        return result
    
    def _parse_output(self, output: str, target: str) -> BanditResult:
        """Parse Bandit JSON output."""
        result = BanditResult(target=target)
        
        try:
            import json
            data = json.loads(output)
            
            results = data.get("results", [])
            result.total_issues = len(results)
            
            for issue in results:
                severity = issue.get("issue_severity", "").lower()
                if severity == "high":
                    result.high_severity += 1
                elif severity == "medium":
                    result.medium_severity += 1
                elif severity == "low":
                    result.low_severity += 1
                
                result.issues.append({
                    "test_id": issue.get("test_id"),
                    "severity": severity,
                    "text": issue.get("issue_text"),
                    "file": issue.get("filename"),
                    "line": issue.get("line_number")
                })
        except Exception:
            pass
        
        return result
