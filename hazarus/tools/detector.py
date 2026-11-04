"""
HAZARUS Tool Detector
Detects installed tools and their versions.
"""

import asyncio
import os
import re
import subprocess
import logging
from typing import Optional, Dict, List
from datetime import datetime
from pathlib import Path
from .registry import ToolRegistry, ToolMetadata, ToolStatus, InstallationType

# Configure logging
logger = logging.getLogger(__name__)

# Common system paths to check for tools
COMMON_SYSTEM_PATHS = [
    "/usr/bin",
    "/usr/local/bin",
    "/opt/bin",
    "/snap/bin",
    "/home/linuxbrew/.linuxbrew/bin",
    "~/.local/bin",
    "/usr/sbin",
    "/sbin",
]

# Alternative command names for tools commonly installed in Parrot OS
ALTERNATIVE_COMMANDS = {
    "zap": ["zap-cli", "zaproxy", "zap.sh"],
    "burpsuite": ["burpsuite", "burp"],
    "wireshark": ["tshark", "wireshark"],
    "metasploit": ["msfconsole", "msfvenom", "msf"],
    "nmap": ["nmap"],
    "nikto": ["nikto"],
    "masscan": ["masscan"],
    "sqlmap": ["sqlmap"],
    "hydra": ["hydra", "hydra-gtk"],
    "john": ["john", "john-the-ripper"],
    "hashcat": ["hashcat"],
    "aircrack-ng": ["aircrack-ng", "airmon-ng", "airodump-ng"],
    "gobuster": ["gobuster"],
    "ffuf": ["ffuf"],
    "whatweb": ["whatweb"],
    "wpscan": ["wpscan"],
    "theharvester": ["theHarvester", "theharvester"],
    "amass": ["amass"],
    "subfinder": ["subfinder"],
    "naabu": ["naabu"],
    "katana": ["katana"],
    "nuclei": ["nuclei"],
    "semgrep": ["semgrep"],
    "gitleaks": ["gitleaks"],
    "trivy": ["trivy"],
    "lynis": ["lynis"],
    "p0f": ["p0f"],
    "arping": ["arping"],
    "fping": ["fping"],
    "feroxbuster": ["feroxbuster"],
    "schemathesis": ["schemathesis"],
    "bandit": ["bandit"],
    "commix": ["commix"],
    "bettercap": ["bettercap"],
    "kismet": ["kismet_server", "kismet"],
    "radare2": ["r2", "radare2"],
    "ghidra": ["analyzeHeadless", "ghidraRun"],
    "frida": ["frida", "frida-server"],
    "bloodhound-python": ["bloodhound-python", "bloodhound"],
    "kerbrute": ["kerbrute"],
    "rustscan": ["rustscan"],
    "ollama": ["ollama"],
}

# GUI tools that may not have CLI commands but are installed via package manager
GUI_TOOLS = {
    "burpsuite": "burpsuite",
    "zap": "zaproxy",
    "wireshark": "wireshark",
    "ghidra": "ghidra",
}


class ToolDetector:
    """Detects installed tools and their versions."""
    
    def __init__(self, registry: Optional[ToolRegistry] = None, debug: bool = False):
        """Initialize tool detector.
        
        Args:
            registry: Tool registry instance (creates default if None)
            debug: Enable debug logging
        """
        self.registry = registry or ToolRegistry()
        self.cache: Dict[str, ToolStatus] = {}
        self.debug = debug
        
        if debug:
            logging.basicConfig(level=logging.DEBUG)
            logger.setLevel(logging.DEBUG)
    
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
            logger.debug(f"Tool '{tool_name}' not found in registry")
            return ToolStatus(
                name=tool_name,
                installed=False,
                compatible=False,
                compatible_reason="Tool not found in registry"
            )
        
        if not tool.detection:
            logger.debug(f"Tool '{tool_name}' has no detection configuration")
            return ToolStatus(
                name=tool_name,
                installed=False,
                compatible=False,
                compatible_reason="No detection configuration"
            )
        
        logger.debug(f"Checking tool: {tool_name}")
        
        # Build comprehensive list of commands to try
        commands_to_try = self._build_command_list(tool_name, tool.detection)
        logger.debug(f"Commands to try for {tool_name}: {commands_to_try}")
        
        # Try each command in order
        for detection_command in commands_to_try:
            try:
                logger.debug(f"Trying command: {detection_command}")
                
                # Check if command exists in PATH
                which_result = await self._run_command(
                    ["which", detection_command],
                    timeout=5
                )
                
                if which_result.returncode != 0:
                    logger.debug(f"Command '{detection_command}' not found in PATH")
                    # Try searching in common system paths
                    command_path = await self._search_in_system_paths(detection_command)
                    if not command_path:
                        continue  # Try next command
                else:
                    command_path = which_result.stdout.strip()
                    logger.debug(f"Found '{detection_command}' at: {command_path}")
                
                # Get version
                version = await self._get_tool_version(
                    detection_command,
                    tool.detection.version_flag,
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
                
                logger.debug(f"Tool '{tool_name}' detected: installed={status.installed}, version={version}")
                self.cache[tool_name] = status
                return status
                
            except Exception as e:
                logger.debug(f"Error checking command '{detection_command}': {e}")
                continue  # Try next command
        
        # All CLI commands failed, check if it's a GUI tool installed via package manager
        if tool_name.lower() in GUI_TOOLS:
            logger.debug(f"Checking if GUI tool '{tool_name}' is installed via package manager")
            package_name = GUI_TOOLS[tool_name.lower()]
            is_installed = await self._check_package_installed(package_name)
            
            if is_installed:
                status = ToolStatus(
                    name=tool_name,
                    installed=True,
                    version=None,  # GUI tools often don't have easy version detection
                    path=f"GUI tool (package: {package_name})",
                    compatible=True,
                    compatible_reason="Installed via package manager (GUI tool)",
                    last_checked=datetime.now().isoformat(),
                    detection_command="package_manager"
                )
                logger.debug(f"GUI tool '{tool_name}' detected via package manager")
                self.cache[tool_name] = status
                return status
        
        # All detection methods failed
        logger.debug(f"Tool '{tool_name}' not found after all detection attempts")
        return ToolStatus(
            name=tool_name,
            installed=False,
            compatible=False,
            compatible_reason="Command not found in PATH or system paths (tried all fallback commands)"
        )
    
    def _build_command_list(self, tool_name: str, detection) -> List[str]:
        """Build comprehensive list of commands to try for tool detection.
        
        Args:
            tool_name: Name of the tool
            detection: ToolDetection configuration
            
        Returns:
            List of command names to try
        """
        commands = []
        
        # Start with primary command
        if detection.command:
            commands.append(detection.command)
        
        # Add configured fallback commands
        if detection.fallback_commands:
            commands.extend(detection.fallback_commands)
        
        # Add alternative commands from the predefined mapping
        tool_key = tool_name.lower()
        if tool_key in ALTERNATIVE_COMMANDS:
            for alt_cmd in ALTERNATIVE_COMMANDS[tool_key]:
                if alt_cmd not in commands:
                    commands.append(alt_cmd)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_commands = []
        for cmd in commands:
            if cmd not in seen:
                seen.add(cmd)
                unique_commands.append(cmd)
        
        return unique_commands
    
    async def _search_in_system_paths(self, command: str) -> Optional[str]:
        """Search for command in common system paths.
        
        Args:
            command: Command name to search for
            
        Returns:
            Path to command if found, None otherwise
        """
        for path in COMMON_SYSTEM_PATHS:
            # Expand ~ to home directory
            expanded_path = Path(path).expanduser()
            
            if not expanded_path.exists():
                continue
            
            command_path = expanded_path / command
            if command_path.exists() and os.access(command_path, os.X_OK):
                logger.debug(f"Found '{command}' in system path: {command_path}")
                return str(command_path)
        
        return None
    
    async def _get_tool_version(self, command: str, version_flag: str, version_pattern: str) -> Optional[str]:
        """Get tool version by running version command.
        
        Args:
            command: Command to run
            version_flag: Flag to get version (e.g., --version)
            version_pattern: Regex pattern to extract version
            
        Returns:
            Version string or None if not found
        """
        try:
            # Some tools use different syntax for version flags
            if version_flag == "-c":
                # Special case for Python imports
                version_result = await self._run_command(
                    [command, version_flag],
                    timeout=5
                )
            else:
                version_result = await self._run_command(
                    [command, version_flag],
                    timeout=5
                )
            
            if version_result.returncode == 0:
                version = self._parse_version(
                    version_result.stdout,
                    version_pattern
                )
                if version:
                    logger.debug(f"Detected version for '{command}': {version}")
                    return version
                else:
                    logger.debug(f"Could not parse version from output: {version_result.stdout[:200]}")
        except Exception as e:
            logger.debug(f"Error getting version for '{command}': {e}")
        
        return None
    
    async def _check_package_installed(self, package_name: str) -> bool:
        """Check if a package is installed via APT package manager.
        
        Args:
            package_name: Name of the package to check
            
        Returns:
            True if package is installed, False otherwise
        """
        try:
            # Use dpkg to check if package is installed
            result = await self._run_command(
                ["dpkg", "-l", package_name],
                timeout=5
            )
            
            # dpkg -l returns 0 even if package not found, so check output
            if result.returncode == 0 and package_name in result.stdout:
                # Check for the "ii" status which means installed
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.startswith('ii') and package_name in line:
                        logger.debug(f"Package '{package_name}' is installed via APT")
                        return True
            
            logger.debug(f"Package '{package_name}' not found via APT")
            return False
        except Exception as e:
            logger.debug(f"Error checking package '{package_name}': {e}")
            return False

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
