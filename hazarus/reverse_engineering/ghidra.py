"""
HAZARUS Ghidra Integration
Binary reverse engineering.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class GhidraResult:
    """Ghidra analysis result."""
    target: str
    functions: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    analyzed_at: datetime = None
    
    def __post_init__(self):
        if self.analyzed_at is None:
            self.analyzed_at = datetime.utcnow()


class GhidraAnalyzer:
    """Ghidra integration for binary analysis."""
    
    def __init__(self):
        self.tool_name = "ghidra"
    
    async def analyze(self, target: str) -> GhidraResult:
        """Analyze binary with Ghidra.
        
        Args:
            target: Target binary file
            
        Returns:
            GhidraResult with analysis data
        """
        result = GhidraResult(target=target)
        
        try:
            # Check if ghidra is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "analyzeHeadless",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("Ghidra not installed")
            
            # Get timeout from config
            from core.config import get_config
            config = get_config()
            timeout = config.get('timeouts.reverse_engineering', 600)
            
            # Build command (simplified)
            cmd = ["analyzeHeadless", target, "-import", target]
            
            # Execute
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=600
            )
            
            # Parse output
            output = stdout.decode()
            result = self._parse_output(output, target)
            
        except Exception as e:
            print(f"Ghidra error: {e}")
        
        return result
    
    def _parse_output(self, output: str, target: str) -> GhidraResult:
        """Parse Ghidra output."""
        result = GhidraResult(target=target)
        
        # Simple parsing
        lines = output.split('\n')
        for line in lines:
            if 'function' in line.lower():
                result.functions.append(line)
            if 'string' in line.lower():
                result.strings.append(line)
        
        return result
