"""
HAZARUS ffuf Integration
HTTP fuzzing and discovery.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class FFUFResult:
    """ffuf scan result."""
    target: str
    discovered_endpoints: List[str] = field(default_factory=list)
    status_codes: Dict[int, int] = field(default_factory=dict)
    response_sizes: Dict[int, int] = field(default_factory=dict)
    scan_duration: float = 0.0
    scanned_at: datetime = None
    
    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class FFUFScanner:
    """ffuf integration for HTTP fuzzing."""
    
    def __init__(self):
        self.tool_name = "ffuf"
    
    async def fuzz(self, target: str, wordlist: Optional[str] = None, threads: int = 50) -> FFUFResult:
        """Fuzz target with ffuf.
        
        Args:
            target: Target URL with FUZZ keyword
            wordlist: Path to wordlist (default: built-in)
            threads: Number of threads (default: 50)
            
        Returns:
            FFUFResult with discovered endpoints
        """
        result = FFUFResult(target=target)
        
        try:
            # Check if ffuf is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "ffuf",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("ffuf not installed")
            
            # Build command
            cmd = [
                "ffuf",
                "-u", target,
                "-t", str(threads),
                "-o", "-",  # Output to stdout
                "-of", "json"  # JSON output
            ]
            
            if wordlist:
                cmd.extend(["-w", wordlist])
            
            # Execute
            start_time = datetime.utcnow()
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=600
            )
            
            end_time = datetime.utcnow()
            result.scan_duration = (end_time - start_time).total_seconds()
            
            # Parse output
            output = stdout.decode()
            result.discovered_endpoints = self._parse_endpoints(output)
            result.status_codes = self._parse_status_codes(output)
            
        except Exception as e:
            print(f"ffuf error: {e}")
        
        return result
    
    def _parse_endpoints(self, output: str) -> List[str]:
        """Parse discovered endpoints from output."""
        endpoints = []
        
        # Simple parsing - can be enhanced for JSON output
        for line in output.split('\n'):
            if 'Status: ' in line:
                parts = line.split()
                if parts:
                    endpoints.append(parts[0])
        
        return endpoints
    
    def _parse_status_codes(self, output: str) -> Dict[int, int]:
        """Parse status codes from output."""
        codes = {}
        
        for line in output.split('\n'):
            if 'Status: ' in line:
                import re
                match = re.search(r'Status: (\d+)', line)
                if match:
                    code = int(match.group(1))
                    codes[code] = codes.get(code, 0) + 1
        
        return codes
