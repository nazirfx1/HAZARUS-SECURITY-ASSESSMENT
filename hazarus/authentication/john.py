"""
HAZARUS John the Ripper Integration
Password hash auditing.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class JohnResult:
    """John the Ripper audit result."""
    hash_file: str
    cracked_hashes: int = 0
    total_hashes: int = 0
    cracked_passwords: List[str] = field(default_factory=list)
    audit_duration: float = 0.0
    audited_at: datetime = None
    
    def __post_init__(self):
        if self.audited_at is None:
            self.audited_at = datetime.utcnow()


class JohnAuditor:
    """John the Ripper integration for password auditing."""
    
    def __init__(self):
        self.tool_name = "john"
    
    async def audit_hashes(self, hash_file: str, wordlist: Optional[str] = None) -> JohnResult:
        """Audit password hashes with John.
        
        Args:
            hash_file: Path to hash file
            wordlist: Path to wordlist
            
        Returns:
            JohnResult with audit results
        """
        result = JohnResult(hash_file=hash_file)
        
        try:
            # Check if john is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "john",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("John the Ripper not installed")
            
            # Build command
            cmd = ["john", hash_file]
            
            if wordlist:
                cmd.extend(["--wordlist", wordlist])
            
            # Execute
            start_time = datetime.utcnow()
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=3600
            )
            
            end_time = datetime.utcnow()
            result.audit_duration = (end_time - start_time).total_seconds()
            
            # Parse output
            output = stdout.decode()
            result = self._parse_output(output, hash_file)
            
        except Exception as e:
            print(f"John error: {e}")
        
        return result
    
    def _parse_output(self, output: str, hash_file: str) -> JohnResult:
        """Parse John output."""
        result = JohnResult(hash_file=hash_file)
        
        # Simple parsing
        lines = output.split('\n')
        for line in lines:
            if 'cracked' in line.lower():
                result.cracked_hashes += 1
        
        return result
