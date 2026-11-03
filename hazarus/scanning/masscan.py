"""
HAZARUS Masscan Integration
Large-scale asynchronous port scanning.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class MasscanResult:
    """Masscan scan result."""
    target: str
    open_ports: List[int] = field(default_factory=list)
    port_services: Dict[int, str] = field(default_factory=dict)
    scan_duration: float = 0.0
    scanned_at: datetime = None
    
    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class MasscanScanner:
    """Masscan integration for high-performance port scanning."""
    
    def __init__(self):
        self.tool_name = "masscan"
    
    async def scan(self, target: str, ports: str = "1-65535", rate: int = 1000) -> MasscanResult:
        """Scan target with Masscan.
        
        Args:
            target: Target IP or network
            ports: Port range (default: 1-65535)
            rate: Scan rate in packets/second (default: 1000)
            
        Returns:
            MasscanResult with open ports
        """
        result = MasscanResult(target=target)
        
        try:
            # Check if masscan is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "masscan",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("Masscan not installed")
            
            # Get timeout from config
            from core.config import get_config
            config = get_config()
            timeout = config.get('timeouts.long', 600)
            
            # Build command
            cmd = [
                "masscan",
                target,
                "-p", ports,
                "--rate", str(rate),
                "-oL", "-"  # Output to stdout
            ]
            
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
            result.open_ports = self._parse_ports(output)
            
        except Exception as e:
            print(f"Masscan error: {e}")
        
        return result
    
    def _parse_ports(self, output: str) -> List[int]:
        """Parse open ports from Masscan output."""
        ports = []
        
        for line in output.split('\n'):
            if line.strip():
                # Masscan output format: Timestamp IP:Port Protocol Status
                parts = line.split()
                if len(parts) >= 2:
                    ip_port = parts[1]
                    if ':' in ip_port:
                        port = int(ip_port.split(':')[1])
                        ports.append(port)
        
        return ports
