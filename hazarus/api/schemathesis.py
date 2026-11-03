"""
HAZARUS Schemathesis Integration
OpenAPI-driven API property testing.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SchemathesisResult:
    """Schemathesis test result."""
    target: str
    total_checks: int = 0
    failed_checks: int = 0
    errors: List[str] = field(default_factory=list)
    scanned_at: datetime = None
    
    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class SchemathesisRunner:
    """Schemathesis integration for API fuzzing."""
    
    def __init__(self):
        self.tool_name = "schemathesis"
    
    async def test_api(self, target: str, schema: Optional[str] = None) -> SchemathesisResult:
        """Test API with Schemathesis.
        
        Args:
            target: Target API URL
            schema: OpenAPI schema URL or path
            
        Returns:
            SchemathesisResult with test results
        """
        result = SchemathesisResult(target=target)
        
        try:
            # Check if schemathesis is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "schemathesis",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("Schemathesis not installed")
            
            # Build command
            cmd = ["schemathesis", "run", target]
            
            if schema:
                cmd.extend(["--base-url", schema])
            
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
            
            output = stdout.decode()
            result = self._parse_output(output, target)
            
        except Exception as e:
            print(f"Schemathesis error: {e}")
        
        return result
    
    def _parse_output(self, output: str, target: str) -> SchemathesisResult:
        """Parse Schemathesis output."""
        result = SchemathesisResult(target=target)
        
        # Simple parsing
        lines = output.split('\n')
        for line in lines:
            if 'checks' in line.lower():
                result.total_checks += 1
            if 'failed' in line.lower():
                result.failed_checks += 1
            if 'error' in line.lower():
                result.errors.append(line)
        
        return result
