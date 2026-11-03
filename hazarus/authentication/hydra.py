"""
HAZARUS Hydra Integration
Authorized authentication testing.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class HydraResult:
    """Hydra test result."""
    target: str
    service: str
    successful_logins: int = 0
    total_attempts: int = 0
    valid_credentials: List[Dict] = field(default_factory=list)
    tested_at: datetime = None
    
    def __post_init__(self):
        if self.tested_at is None:
            self.tested_at = datetime.utcnow()


class HydraTester:
    """Hydra integration for authentication testing."""
    
    def __init__(self):
        self.tool_name = "hydra"
    
    async def test_auth(self, target: str, service: str, username: str, wordlist: str) -> HydraResult:
        """Test authentication with Hydra.
        
        Args:
            target: Target host
            service: Service to test (ssh, ftp, http, etc.)
            username: Username to test
            wordlist: Password wordlist
            
        Returns:
            HydraResult with test results
        """
        result = HydraResult(target=target, service=service)
        
        try:
            # Check if hydra is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "hydra",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("Hydra not installed")
            
            # Build command
            cmd = [
                "hydra",
                "-l", username,
                "-P", wordlist,
                target,
                service
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
            result = self._parse_output(output, target, service)
            
        except Exception as e:
            print(f"Hydra error: {e}")
        
        return result
    
    def _parse_output(self, output: str, target: str, service: str) -> HydraResult:
        """Parse Hydra output."""
        result = HydraResult(target=target, service=service)
        
        # Simple parsing
        lines = output.split('\n')
        for line in lines:
            if 'valid' in line.lower() or 'password' in line.lower():
                result.successful_logins += 1
        
        return result
