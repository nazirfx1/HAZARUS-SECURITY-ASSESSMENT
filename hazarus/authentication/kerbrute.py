"""
HAZARUS Kerbrute Integration
Active Directory authentication assessment.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class KerbruteResult:
    """Kerbrute audit result."""
    target: str
    valid_users: List[str] = field(default_factory=list)
    valid_passwords: List[str] = field(default_factory=list)
    total_tested: int = 0
    audited_at: datetime = None
    
    def __post_init__(self):
        if self.audited_at is None:
            self.audited_at = datetime.utcnow()


class KerbruteAuditor:
    """Kerbrute integration for AD assessment."""
    
    def __init__(self):
        self.tool_name = "kerbrute"
    
    async def enum_users(self, target: str, userlist: str) -> KerbruteResult:
        """Enumerate valid users in AD.
        
        Args:
            target: Target domain
            userlist: Path to username list
            
        Returns:
            KerbruteResult with valid users
        """
        result = KerbruteResult(target=target)
        
        try:
            # Check if kerbrute is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "kerbrute",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("Kerbrute not installed")
            
            # Build command
            cmd = [
                "kerbrute",
                "userenum",
                "--domain", target,
                userlist
            ]
            
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
            print(f"Kerbrute error: {e}")
        
        return result
    
    def _parse_output(self, output: str, target: str) -> KerbruteResult:
        """Parse Kerbrute output."""
        result = KerbruteResult(target=target)
        
        # Simple parsing
        lines = output.split('\n')
        for line in lines:
            if 'valid' in line.lower():
                parts = line.split()
                if parts:
                    result.valid_users.append(parts[-1])
        
        return result
