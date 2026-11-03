"""
HAZARUS LinPEAS Integration
Linux privilege escalation exposure discovery.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class LinPEASResult:
    """LinPEAS scan result."""
    target: str
    findings: List[str] = field(default_factory=list)
    high_risk: int = 0
    medium_risk: int = 0
    low_risk: int = 0
    scanned_at: datetime = None
    
    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class LinPEASScanner:
    """LinPEAS integration for privilege escalation detection."""
    
    def __init__(self):
        self.tool_name = "linpeas"
    
    async def scan(self, target: str = "/") -> LinPEASResult:
        """Scan system with LinPEAS.
        
        Args:
            target: Target directory (default: /)
            
        Returns:
            LinPEASResult with privilege escalation findings
        """
        result = LinPEASResult(target=target)
        
        try:
            # Check if linpeas is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "linpeas",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("LinPEAS not installed")
            
            # Build command
            cmd = ["linpeas", "-a", target]
            
            # Execute
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=600
            )
            
            # Parse output
            output = stdout.decode()
            result = self._parse_output(output, target)
            
        except Exception as e:
            print(f"LinPEAS error: {e}")
        
        return result
    
    def _parse_output(self, output: str, target: str) -> LinPEASResult:
        """Parse LinPEAS output."""
        result = LinPEASResult(target=target)
        
        # Simple parsing - LinPEAS has color-coded output
        lines = output.split('\n')
        for line in lines:
            if '[+]' in line or '[!]' in line:
                result.findings.append(line)
                if 'CRITICAL' in line or 'RED' in line:
                    result.high_risk += 1
                elif 'YELLOW' in line:
                    result.medium_risk += 1
                else:
                    result.low_risk += 1
        
        return result
