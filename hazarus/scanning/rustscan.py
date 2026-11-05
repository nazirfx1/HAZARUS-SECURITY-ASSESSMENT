"""
HAZARUS RustScan Integration
Fast port discovery + Nmap integration.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime

from hazarus.core.config import get_config
config = get_config()


@dataclass
class RustScanResult:
    """RustScan scan result."""
    target: str
    open_ports: List[int] = field(default_factory=list)
    scan_duration: float = 0.0
    scanned_at: datetime = None
    
    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class RustScanScanner:
    """RustScan integration for fast port scanning."""
    
    def __init__(self):
        self.tool_name = "rustscan"
    
    async def scan(self, target: str, ports: str = "1-65535") -> RustScanResult:
        """Scan target with RustScan.
        
        Args:
            target: Target IP or network
            ports: Port range (default: 1-65535)
            
        Returns:
            RustScanResult with open ports
        """
        result = RustScanResult(target=target)
        
        try:
            # Check if rustscan is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "rustscan",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("RustScan not installed")
            
            # Build command
            cmd = ["rustscan", "-a", target, "-r", ports]
            
            # Execute
            start_time = datetime.utcnow()
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=config.get('timeouts.long', 300)
            )
            
            end_time = datetime.utcnow()
            result.scan_duration = (end_time - start_time).total_seconds()
            
            # Parse output
            output = stdout.decode()
            result.open_ports = self._parse_ports(output)
            
        except Exception as e:
            print(f"RustScan error: {e}")
        
        return result
    
    def _parse_ports(self, output: str) -> List[int]:
        """Parse open ports from RustScan output."""
        ports = []
        
        for line in output.split('\n'):
            if 'open' in line.lower():
                import re
                match = re.search(r'(\d+)', line)
                if match:
                    ports.append(int(match.group(1)))
        
        return ports
