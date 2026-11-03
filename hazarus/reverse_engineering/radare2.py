"""
HAZARUS radare2 Integration
Binary analysis and disassembly.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Radare2Result:
    """radare2 analysis result."""
    target: str
    functions: List[str] = field(default_factory=list)
    disassembly: List[str] = field(default_factory=list)
    analyzed_at: datetime = None
    
    def __post_init__(self):
        if self.analyzed_at is None:
            self.analyzed_at = datetime.utcnow()


class Radare2Analyzer:
    """radare2 integration for binary analysis."""
    
    def __init__(self):
        self.tool_name = "radare2"
    
    async def analyze(self, target: str) -> Radare2Result:
        """Analyze binary with radare2.
        
        Args:
            target: Target binary file
            
        Returns:
            Radare2Result with analysis data
        """
        result = Radare2Result(target=target)
        
        try:
            # Check if radare2 is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "r2",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("radare2 not installed")
            
            # Build command
            cmd = ["r2", "-q", "-c", "afl", target]
            
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
            print(f"radare2 error: {e}")
        
        return result
    
    def _parse_output(self, output: str, target: str) -> Radare2Result:
        """Parse radare2 output."""
        result = Radare2Result(target=target)
        
        # Simple parsing
        lines = output.split('\n')
        for line in lines:
            if line.strip():
                result.functions.append(line)
        
        return result
