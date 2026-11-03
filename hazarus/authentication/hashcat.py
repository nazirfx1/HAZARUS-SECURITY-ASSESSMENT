"""
HAZARUS Hashcat Integration
GPU-accelerated hash auditing.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class HashcatResult:
    """Hashcat audit result."""
    hash_file: str
    cracked_hashes: int = 0
    total_hashes: int = 0
    cracked_passwords: List[str] = field(default_factory=list)
    audit_duration: float = 0.0
    audited_at: datetime = None
    
    def __post_init__(self):
        if self.audited_at is None:
            self.audited_at = datetime.utcnow()


class HashcatAuditor:
    """Hashcat integration for password auditing."""
    
    def __init__(self):
        self.tool_name = "hashcat"
    
    async def audit_hashes(self, hash_file: str, wordlist: Optional[str] = None) -> HashcatResult:
        """Audit password hashes with Hashcat.
        
        Args:
            hash_file: Path to hash file
            wordlist: Path to wordlist
            
        Returns:
            HashcatResult with audit results
        """
        result = HashcatResult(hash_file=hash_file)
        
        try:
            # Check if hashcat is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "hashcat",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("Hashcat not installed")
            
            # Get timeout from config
            from core.config import get_config
            config = get_config()
            timeout = config.get('timeouts.password_cracking', 3600)
            
            # Build command
            cmd = ["hashcat", hash_file]
            
            if wordlist:
                cmd.extend([wordlist])
            else:
                cmd.extend(["-a", "0"])  # Straight attack mode
            
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
            print(f"Hashcat error: {e}")
        
        return result
    
    def _parse_output(self, output: str, hash_file: str) -> HashcatResult:
        """Parse Hashcat output."""
        result = HashcatResult(hash_file=hash_file)
        
        # Simple parsing
        lines = output.split('\n')
        for line in lines:
            if 'Cracked' in line:
                result.cracked_hashes += 1
        
        return result
