"""
HAZARUS GDB Integration
Debugging and runtime analysis.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class GDBResult:
    """GDB analysis result."""
    target: str
    breakpoints: List[str] = field(default_factory=list)
    registers: Dict[str, str] = field(default_factory=dict)
    analyzed_at: datetime = None
    
    def __post_init__(self):
        if self.analyzed_at is None:
            self.analyzed_at = datetime.utcnow()


class GDBDebugger:
    """GDB integration for debugging."""
    
    def __init__(self):
        self.tool_name = "gdb"
    
    async def analyze(self, target: str) -> GDBResult:
        """Analyze binary with GDB.
        
        Args:
            target: Target binary file
            
        Returns:
            GDBResult with analysis data
        """
        result = GDBResult(target=target)
        
        try:
            # Check if gdb is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "gdb",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("GDB not installed")
            
            # Get timeout from config
            from core.config import get_config
            config = get_config()
            timeout = config.get('timeouts.reverse_engineering', 300)
            
            # Build command (simplified)
            cmd = ["gdb", "-batch", "-ex", "info functions", target]
            
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
            print(f"GDB error: {e}")
        
        return result
    
    def _parse_output(self, output: str, target: str) -> GDBResult:
        """Parse GDB output."""
        result = GDBResult(target=target)
        
        # Simple parsing
        lines = output.split('\n')
        for line in lines:
            if 'function' in line.lower():
                result.breakpoints.append(line)
        
        return result
