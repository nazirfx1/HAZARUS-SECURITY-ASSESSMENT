"""
HAZARUS Feroxbuster Integration
Recursive content discovery.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class FeroxbusterResult:
    """Feroxbuster scan result."""
    target: str
    discovered_paths: List[str] = field(default_factory=list)
    status_codes: Dict[int, int] = field(default_factory=dict)
    scan_duration: float = 0.0
    scanned_at: datetime = None
    
    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class FeroxbusterScanner:
    """Feroxbuster integration for content discovery."""
    
    def __init__(self):
        self.tool_name = "feroxbuster"
    
    async def scan(self, target: str, wordlist: Optional[str] = None, threads: int = 10) -> FeroxbusterResult:
        """Scan target with Feroxbuster.
        
        Args:
            target: Target URL
            wordlist: Path to wordlist (default: built-in)
            threads: Number of threads (default: 10)
            
        Returns:
            FeroxbusterResult with discovered paths
        """
        result = FeroxbusterResult(target=target)
        
        try:
            # Check if feroxbuster is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "feroxbuster",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("Feroxbuster not installed")
            
            # Get timeout from config
            from core.config import get_config
            config = get_config()
            timeout = config.get('timeouts.advanced_web', 600)
            
            # Build command
            cmd = [
                "feroxbuster",
                "-u", target,
                "-t", str(threads),
                "-q",  # Quiet mode
                "-n",  # Don't filter out non-html responses
                "-x", "php,html,js"  # Extensions
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
            result.discovered_paths = self._parse_paths(output)
            result.status_codes = self._parse_status_codes(output)
            
        except Exception as e:
            print(f"Feroxbuster error: {e}")
        
        return result
    
    def _parse_paths(self, output: str) -> List[str]:
        """Parse discovered paths from output."""
        paths = []
        
        for line in output.split('\n'):
            if '200' in line or '301' in line or '302' in line:
                parts = line.split()
                if parts:
                    paths.append(parts[0])
        
        return paths
    
    def _parse_status_codes(self, output: str) -> Dict[int, int]:
        """Parse status codes from output."""
        codes = {}
        
        for line in output.split('\n'):
            if 'Status: ' in line:
                # Extract status code
                import re
                match = re.search(r'Status: (\d+)', line)
                if match:
                    code = int(match.group(1))
                    codes[code] = codes.get(code, 0) + 1
        
        return codes
