"""
HAZARUS Bettercap Integration
Network protocol assessment.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class BettercapResult:
    """Bettercap analysis result."""
    target: str
    captured_packets: int = 0
    protocols: List[str] = field(default_factory=list)
    analyzed_at: datetime = None
    
    def __post_init__(self):
        if self.analyzed_at is None:
            self.analyzed_at = datetime.utcnow()


class BettercapAnalyzer:
    """Bettercap integration for network assessment."""
    
    def __init__(self):
        self.tool_name = "bettercap"
    
    async def analyze(self, target: str) -> BettercapResult:
        """Analyze network with Bettercap.
        
        Args:
            target: Target interface or network
            
        Returns:
            BettercapResult with analysis data
        """
        result = BettercapResult(target=target)
        
        try:
            # Check if bettercap is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "bettercap",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("Bettercap not installed")
            
            # Get timeout from config
            from core.config import get_config
            config = get_config()
            timeout = config.get('timeouts.wireless', 300)
            
            # Build command
            cmd = ["bettercap", "-iface", target]
            
            # Execute
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300
            )
            
            # Parse output
            output = stdout.decode()
            result = self._parse_output(output, target)
            
        except Exception as e:
            print(f"Bettercap error: {e}")
        
        return result
    
    def _parse_output(self, output: str, target: str) -> BettercapResult:
        """Parse Bettercap output."""
        result = BettercapResult(target=target)
        
        # Simple parsing
        lines = output.split('\n')
        for line in lines:
            if 'packet' in line.lower():
                result.captured_packets += 1
        
        return result
