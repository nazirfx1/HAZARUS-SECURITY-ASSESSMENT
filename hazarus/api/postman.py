"""
HAZARUS Postman Integration
API collections and automated workflows.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PostmanResult:
    """Postman/Newman test result."""
    collection: str
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    response_time: float = 0.0
    scanned_at: datetime = None
    
    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class PostmanRunner:
    """Postman/Newman integration for API testing."""
    
    def __init__(self):
        self.tool_name = "newman"
    
    async def run_collection(self, collection_file: str, environment: Optional[str] = None) -> PostmanResult:
        """Run Postman collection with Newman.
        
        Args:
            collection_file: Path to Postman collection JSON
            environment: Path to environment JSON
            
        Returns:
            PostmanResult with test results
        """
        result = PostmanResult(collection=collection_file)
        
        try:
            # Check if newman is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "newman",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("Newman not installed")
            
            # Build command
            cmd = ["newman", "run", collection_file]
            
            if environment:
                cmd.extend(["-e", environment])
            
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
            result.response_time = (end_time - start_time).total_seconds()
            
            # Parse output
            output = stdout.decode()
            result = self._parse_output(output, collection_file)
            
        except Exception as e:
            print(f"Newman error: {e}")
        
        return result
    
    def _parse_output(self, output: str, collection: str) -> PostmanResult:
        """Parse Newman output."""
        result = PostmanResult(collection=collection)
        
        # Simple parsing
        lines = output.split('\n')
        for line in lines:
            if 'tests' in line.lower():
                result.total_tests += 1
            if 'passed' in line.lower():
                result.passed_tests += 1
            if 'failed' in line.lower():
                result.failed_tests += 1
        
        return result
