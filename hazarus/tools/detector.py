"""
HAZARUS Tool Detector
Detects installed tools and their versions.
"""

import asyncio
import re
import subprocess
from typing import Optional, Dict
from datetime import datetime
from .registry import ToolRegistry, ToolMetadata, ToolStatus


class ToolDetector:
    """Detects installed tools and their versions."""
    
    def __init__(self, registry: Optional[ToolRegistry] = None):
        """Initialize tool detector.
        
        Args:
            registry: Tool registry instance (creates default if None)
        """
        self.registry = registry or ToolRegistry()
        self.cache: Dict[str, ToolStatus] = {}
    
    async def check_tool(self, tool_name: str) -> ToolStatus:
        """Check if a tool is installed and get its version with fallback commands.
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            ToolStatus with installation status and version
        """
        # Check cache first
        if tool_name in self.cache:
            return self.cache[tool_name]
        
        tool = self.registry.get_tool(tool_name)
        if not tool:
            return ToolStatus(
                name=tool_name,
                installed=False,
                compatible=False,
                compatible_reason="Tool not found in registry"
            )
        
        if not tool.detection:
            return ToolStatus(
                name=tool_name,
                installed=False,
                compatible=False,
                compatible_reason="No detection configuration"
            )
        
        # Build list of commands to try (primary + fallbacks)
        commands_to_try = [tool.detection.command] + tool.detection.fallback_commands
        
        # Try each command in order
        for detection_command in commands_to_try:
            try:
                # Check if command exists
                which_result = await self._run_command(
                    ["which", detection_command]
                )
                
                if which_result.returncode != 0:
                    continue  # Try next command
                
                # Get command path
                command_path = which_result.stdout.strip()
                
                # Get version
                version_result = await self._run_command(
                    [detection_command, tool.detection.version_flag]
                )
                
                version = None
                if version_result.returncode == 0:
                    version = self._parse_version(
                        version_result.stdout,
                        tool.detection.version_pattern
                    )
                
                # Check compatibility
                compatible, reason = self._check_compatibility(tool, version)
                
                status = ToolStatus(
                    name=tool_name,
                    installed=True,
                    version=version,
                    path=command_path,
                    compatible=compatible,
                    compatible_reason=reason,
                    last_checked=datetime.now().isoformat(),
                    detection_command=detection_command
                )
                
                self.cache[tool_name] = status
                return status
                
            except Exception as e:
                continue  # Try next command
        
        # All commands failed
        return ToolStatus(
            name=tool_name,
            installed=False,
            compatible=False,
            compatible_reason="Command not found in PATH (tried all fallback commands)"
        )
    
    async def check_all_tools(self) -> Dict[str, ToolStatus]:
        """Check all registered tools.
        
        Returns:
            Dictionary mapping tool names to their status
        """
        tools = self.registry.get_all_tools()
        results = {}
        
        for tool_name in tools.keys():
            results[tool_name] = await self.check_tool(tool_name)
        
        return results
    
    async def check_required_tools(self) -> Dict[str, ToolStatus]:
        """Check only required tools.
        
        Returns:
            Dictionary mapping tool names to their status
        """
        tools = self.registry.get_required_tools()
        results = {}
        
        for tool_name in tools.keys():
            results[tool_name] = await self.check_tool(tool_name)
        
        return results
    
    async def check_missing_tools(self) -> Dict[str, ToolStatus]:
        """Get list of missing tools.
        
        Returns:
            Dictionary of tool names that are not installed
        """
        all_status = await self.check_all_tools()
        return {
            name: status for name, status in all_status.items()
            if not status.installed
        }
    
    async def check_incompatible_tools(self) -> Dict[str, ToolStatus]:
        """Get list of installed but incompatible tools.
        
        Returns:
            Dictionary of tool names that are incompatible
        """
        all_status = await self.check_all_tools()
        return {
            name: status for name, status in all_status.items()
            if status.installed and not status.compatible
        }
    
    def clear_cache(self):
        """Clear the detection cache."""
        self.cache.clear()
    
    async def _run_command(self, command: list, timeout: int = 10) -> subprocess.CompletedProcess:
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
    
    def _parse_version(self, output: str, pattern: str) -> Optional[str]:
        """Parse version from command output.
        
        Args:
            output: Command output string
            pattern: Regex pattern to extract version
            
        Returns:
            Version string or None if not found
        """
        try:
            match = re.search(pattern, output)
            if match:
                return match.group(1)
        except (re.error, IndexError):
            pass
        return None
    
    def _check_compatibility(self, tool: ToolMetadata, version: Optional[str]) -> tuple[bool, Optional[str]]:
        """Check if tool version is compatible.
        
        Args:
            tool: Tool metadata
            version: Detected version string
            
        Returns:
            Tuple of (compatible, reason)
        """
        if not version:
            return True, None  # Can't determine compatibility
        
        if not tool.installation or not tool.installation.version:
            return True, None  # No version constraint
        
        # Parse version constraint
        constraint = tool.installation.version
        if '+' in constraint:
            min_version = constraint.replace('+', '')
            if self._compare_versions(version, min_version) >= 0:
                return True, None
            else:
                return False, f"Version {version} < required {min_version}"
        
        return True, None
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings.
        
        Args:
            v1: First version
            v2: Second version
            
        Returns:
            -1 if v1 < v2, 0 if equal, 1 if v1 > v2
        """
        v1_parts = [int(x) for x in v1.split('.')]
        v2_parts = [int(x) for x in v2.split('.')]
        
        # Pad shorter version with zeros
        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts.extend([0] * (max_len - len(v1_parts)))
        v2_parts.extend([0] * (max_len - len(v2_parts)))
        
        for a, b in zip(v1_parts, v2_parts):
            if a < b:
                return -1
            elif a > b:
                return 1
        
        return 0
