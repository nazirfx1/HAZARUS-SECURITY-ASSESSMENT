"""
HAZARUS SpiderFoot Integration
Automated OSINT correlation.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime

from core.config import get_config
config = get_config()


@dataclass
class SpiderFootResult:
    """SpiderFoot scan result."""
    target: str
    data_types: List[str] = field(default_factory=list)
    total_entities: int = 0
    correlated_data: Dict[str, List] = field(default_factory=dict)
    scanned_at: datetime = None
    
    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class SpiderFootScanner:
    """SpiderFoot integration for OSINT correlation."""
    
    def __init__(self):
        self.tool_name = "spiderfoot"
    
    async def scan(self, target: str, modules: Optional[List[str]] = None) -> SpiderFootResult:
        """Scan target with SpiderFoot.
        
        Args:
            target: Target domain or IP
            modules: List of modules to use
            
        Returns:
            SpiderFootResult with correlated OSINT data
        """
        result = SpiderFootResult(target=target)
        
        try:
            # Check if spiderfoot is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "sf",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("SpiderFoot not installed")
            
            # Build command
            cmd = ["sf", "-s", target]
            
            if modules:
                cmd.extend(["-m", ",".join(modules)])
            
            # Execute
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=config.get('timeouts.subdomain_discovery', 600)
            )
            
            # Parse output
            output = stdout.decode()
            result = self._parse_output(output, target)
            
        except Exception as e:
            print(f"SpiderFoot error: {e}")
        
        return result
    
    def _parse_output(self, output: str, target: str) -> SpiderFootResult:
        """Parse SpiderFoot output."""
        result = SpiderFootResult(target=target)
        
        # Simple parsing
        lines = output.split('\n')
        for line in lines:
            if 'entity' in line.lower():
                result.total_entities += 1
        
        return result
