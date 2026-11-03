"""
HAZARUS Lynis Integration
Linux security configuration auditing.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class LynisResult:
    """Lynis scan result."""
    target: str
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    scanned_at: datetime = None
    
    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class LynisScanner:
    """Lynis integration for security auditing."""
    
    def __init__(self):
        self.tool_name = "lynis"
    
    async def audit(self, target: str = "/") -> LynisResult:
        """Audit system with Lynis.
        
        Args:
            target: Target directory (default: /)
            
        Returns:
            LynisResult with audit findings
        """
        result = LynisResult(target=target)
        
        try:
            # Check if lynis is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "lynis",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("Lynis not installed")
            
            # Get timeout from config
            from core.config import get_config
            config = get_config()
            timeout = config.get('timeouts.post_assessment', 600)
            
            # Build command
            cmd = ["lynis", "audit", "system", "-Q"]
            
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
            print(f"Lynis error: {e}")
        
        return result
    
    def _parse_output(self, output: str, target: str) -> LynisResult:
        """Parse Lynis output."""
        result = LynisResult(target=target)
        
        # Simple parsing
        lines = output.split('\n')
        for line in lines:
            if 'tests' in line.lower():
                result.total_tests += 1
            if 'warning' in line.lower():
                result.warnings.append(line)
            if 'suggestion' in line.lower():
                result.suggestions.append(line)
            if 'suggestion found' in line.lower():
                result.failed_tests += 1
            if 'hardening' in line.lower():
                result.passed_tests += 1
        
        return result
