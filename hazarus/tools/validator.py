"""
HAZARUS Tool Validator
Validates that tools are working correctly.
"""

import asyncio
import subprocess
from typing import Optional, Dict
from .registry import ToolRegistry, ToolMetadata, ToolStatus


class ToolValidator:
    """Validates that tools are working correctly."""
    
    def __init__(self, registry: Optional[ToolRegistry] = None):
        """Initialize tool validator.
        
        Args:
            registry: Tool registry instance (creates default if None)
        """
        self.registry = registry or ToolRegistry()
    
    async def validate_tool(self, tool_name: str) -> bool:
        """Validate that a tool is working correctly.
        
        Args:
            tool_name: Name of the tool to validate
            
        Returns:
            True if tool is working, False otherwise
        """
        tool = self.registry.get_tool(tool_name)
        if not tool or not tool.validation:
            return True  # No validation defined
        
        try:
            # Run test command
            result = await self._run_command(
                tool.validation.test_command.split()
            )
            
            # Check exit code
            if result.returncode != tool.validation.exit_code:
                return False
            
            # Check expected output if specified
            if tool.validation.expected_output:
                if tool.validation.expected_output not in result.stdout:
                    return False
            
            return True
            
        except Exception as e:
            print(f"Validation failed for {tool_name}: {e}")
            return False
    
    async def validate_all(self) -> Dict[str, bool]:
        """Validate all installed tools.
        
        Returns:
            Dictionary mapping tool names to validation results
        """
        from .detector import ToolDetector
        detector = ToolDetector(self.registry)
        
        results = {}
        all_status = await detector.check_all_tools()
        
        for tool_name, status in all_status.items():
            if status.installed:
                results[tool_name] = await self.validate_tool(tool_name)
            else:
                results[tool_name] = False  # Not installed, not valid
        
        return results
    
    async def validate_required(self) -> Dict[str, bool]:
        """Validate only required tools.
        
        Returns:
            Dictionary mapping tool names to validation results
        """
        from .detector import ToolDetector
        detector = ToolDetector(self.registry)
        
        results = {}
        required_status = await detector.check_required_tools()
        
        for tool_name, status in required_status.items():
            if status.installed:
                results[tool_name] = await self.validate_tool(tool_name)
            else:
                results[tool_name] = False
        
        return results
    
    async def _run_command(self, command: list, timeout: int = 30) -> subprocess.CompletedProcess:
        """Run a command asynchronously.
        
        Args:
            command: Command to run as list
            timeout: Timeout in seconds
            
        Returns:
            CompletedProcess with stdout and stderr
        """
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            return subprocess.CompletedProcess(
                args=command,
                returncode=process.returncode,
                stdout=stdout.decode(),
                stderr=stderr.decode()
            )
        except asyncio.TimeoutError:
            if process:
                process.kill()
            raise TimeoutError(f"Command timed out: {' '.join(command)}")
