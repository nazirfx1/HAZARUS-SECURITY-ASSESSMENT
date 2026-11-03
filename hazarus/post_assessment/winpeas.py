"""
HAZARUS WinPEAS Integration
Windows privilege escalation exposure discovery.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime

from core.config import get_config
config = get_config()


@dataclass
class WinPEASResult:
    """WinPEAS scan result."""
    target: str
    findings: List[str] = field(default_factory=list)
    high_risk: int = 0
    medium_risk: int = 0
    low_risk: int = 0
    scanned_at: datetime = None
    
    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class WinPEASScanner:
    """WinPEAS integration for Windows privilege escalation."""
    
    def __init__(self):
        self.tool_name = "winpeas"
    
    async def scan(self, target: str = "C:\\") -> WinPEASResult:
        """Scan Windows system with WinPEAS.
        
        Args:
            target: Target directory (default: C:\\)
            
        Returns:
            WinPEASResult with privilege escalation findings
        """
        result = WinPEASResult(target=target)
        
        try:
            # Check if winpeas is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "winpeas",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("WinPEAS not installed")
            
            # Build command
            cmd = ["winpeas", target]
            
            # Execute
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=config.get('timeouts.post_assessment', 600)
            )
            
            # Parse output
            output = stdout.decode()
            result = self._parse_output(output, target)
            
        except Exception as e:
            print(f"WinPEAS error: {e}")
        
        return result
    
    def _parse_output(self, output: str, target: str) -> WinPEASResult:
        """Parse WinPEAS output."""
        result = WinPEASResult(target=target)
        
        # Simple parsing
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
