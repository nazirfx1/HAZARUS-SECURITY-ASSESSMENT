"""
HAZARUS Tool Installer
Automated installation of external security tools.
"""

import asyncio
import os
import subprocess
import shutil
from typing import Optional, Dict, List
from pathlib import Path
from .registry import ToolRegistry, ToolMetadata, ToolStatus, InstallationType
from .detector import ToolDetector


class ToolInstaller:
    """Automated installer for external tools."""
    
    def __init__(self, registry: Optional[ToolRegistry] = None):
        """Initialize tool installer.
        
        Args:
            registry: Tool registry instance (creates default if None)
        """
        self.registry = registry or ToolRegistry()
        self.detector = ToolDetector(registry)
        self.installers = {
            InstallationType.APT: self._install_apt,
            InstallationType.PIP: self._install_pip,
            InstallationType.GITHUB: self._install_github,
            InstallationType.SNAP: self._install_snap,
            InstallationType.MANUAL: self._install_manual,
        }
    
    async def install_tool(self, tool_name: str, sudo: bool = None) -> ToolStatus:
        """Install a single tool.
        
        Args:
            tool_name: Name of the tool to install
            sudo: Whether to use sudo (None = auto-detect based on tool config)
            
        Returns:
            ToolStatus after installation attempt
        """
        tool = self.registry.get_tool(tool_name)
        if not tool:
            return ToolStatus(
                name=tool_name,
                installed=False,
                compatible=False,
                compatible_reason="Tool not found in registry"
            )
        
        if not tool.installation:
            return ToolStatus(
                name=tool_name,
                installed=False,
                compatible=False,
                compatible_reason="No installation configuration"
            )
        
        # Determine sudo requirement
        use_sudo = sudo if sudo is not None else tool.installation.sudo_required
        
        # Check if already installed
        current_status = await self.detector.check_tool(tool_name)
        if current_status.installed:
            return current_status
        
        # Install using appropriate method
        installer_func = self.installers.get(tool.installation.type)
        if not installer_func:
            return ToolStatus(
                name=tool_name,
                installed=False,
                compatible=False,
                compatible_reason=f"Unsupported installation type: {tool.installation.type}"
            )
        
        try:
            success = await installer_func(tool, use_sudo)
            
            if success:
                # Verify installation
                new_status = await self.detector.check_tool(tool_name)
                return new_status
            else:
                return ToolStatus(
                    name=tool_name,
                    installed=False,
                    compatible=False,
                    compatible_reason="Installation failed"
                )
        except Exception as e:
            return ToolStatus(
                name=tool_name,
                installed=False,
                compatible=False,
                compatible_reason=f"Installation error: {str(e)}"
            )
    
    async def install_all_missing(self, sudo: bool = None) -> Dict[str, ToolStatus]:
        """Install all missing tools.
        
        Args:
            sudo: Whether to use sudo (None = auto-detect)
            
        Returns:
            Dictionary mapping tool names to installation status
        """
        missing = await self.detector.check_missing_tools()
        results = {}
        
        for tool_name in missing.keys():
            results[tool_name] = await self.install_tool(tool_name, sudo)
        
        return results
    
    async def install_required(self, sudo: bool = None) -> Dict[str, ToolStatus]:
        """Install only required tools.
        
        Args:
            sudo: Whether to use sudo (None = auto-detect)
            
        Returns:
            Dictionary mapping tool names to installation status
        """
        required_tools = self.registry.get_required_tools()
        results = {}
        
        for tool_name in required_tools.keys():
            status = await self.detector.check_tool(tool_name)
            if not status.installed:
                results[tool_name] = await self.install_tool(tool_name, sudo)
            else:
                results[tool_name] = status
        
        return results
    
    async def _install_apt(self, tool: ToolMetadata, use_sudo: bool) -> bool:
        """Install tool via APT package manager.
        
        Args:
            tool: Tool metadata
            use_sudo: Whether to use sudo
            
        Returns:
            True if successful, False otherwise
        """
        if not tool.installation or not tool.installation.package:
            return False
        
        cmd = ["apt", "update"]
        if use_sudo:
            cmd.insert(0, "sudo")
        
        # Update package list
        await self._run_command(cmd)
        
        # Install package
        cmd = ["apt", "install", "-y", tool.installation.package]
        if use_sudo:
            cmd.insert(0, "sudo")
        
        result = await self._run_command(cmd)
        return result.returncode == 0
    
    async def _install_pip(self, tool: ToolMetadata, use_sudo: bool) -> bool:
        """Install tool via pip.
        
        Args:
            tool: Tool metadata
            use_sudo: Whether to use sudo (for system install)
            
        Returns:
            True if successful, False otherwise
        """
        if not tool.installation or not tool.installation.package:
            return False
        
        try:
            # Use pip with --user by default
            cmd = ["pip", "install", "--user", tool.installation.package]
            
            if use_sudo:
                # System-wide install
                cmd = ["pip", "install", tool.installation.package]
                cmd.insert(0, "sudo")
            
            result = await self._run_command(cmd)
            
            if result.returncode != 0:
                print(f"Pip install failed: {result.stderr}")
                return False
            
            return True
        except Exception as e:
            print(f"Pip install error: {e}")
            return False
    
    async def _install_github(self, tool: ToolMetadata, use_sudo: bool) -> bool:
        """Install tool from GitHub releases.
        
        Args:
            tool: Tool metadata
            use_sudo: Whether to use sudo
            
        Returns:
            True if successful, False otherwise
        """
        if not tool.installation or not tool.installation.repo:
            return False
        
        try:
            from .downloader import GitHubDownloader
            
            downloader = GitHubDownloader()
            
            # Download asset
            print(f"  Downloading {tool.name} from GitHub...")
            asset_path = await downloader.download_latest_release(
                tool.installation.repo,
                tool.installation.asset_pattern
            )
            
            if not asset_path:
                print(f"  Download failed for {tool.name}")
                return False
            
            print(f"  Extracting {tool.name}...")
            # Extract
            extract_dir = await downloader.extract_archive(asset_path)
            
            if not extract_dir:
                print(f"  Extraction failed for {tool.name}")
                return False
            
            # Install
            install_path = tool.installation.install_path or "/usr/local/bin"
            
            if use_sudo:
                # System-wide install
                install_path = tool.installation.install_path or "/usr/local/bin"
                cmd = ["sudo", "cp", "-r", f"{extract_dir}/*", install_path]
                result = await self._run_command(cmd)
                success = result.returncode == 0
                if not success:
                    print(f"  Install failed: {result.stderr}")
            else:
                # User-space install
                install_path = Path.home() / ".local" / "bin"
                install_path.mkdir(parents=True, exist_ok=True)
                
                # Copy binaries
                copied = False
                for file in Path(extract_dir).glob("*"):
                    if file.is_file() and os.access(file, os.X_OK):
                        shutil.copy(file, install_path / file.name)
                        copied = True
                
                success = copied
            
            # Cleanup
            shutil.rmtree(asset_path.parent, ignore_errors=True)
            
            return success
            
        except Exception as e:
            print(f"  GitHub install error for {tool.name}: {e}")
            return False
    
    async def _install_snap(self, tool: ToolMetadata, use_sudo: bool) -> bool:
        """Install tool via Snap.
        
        Args:
            tool: Tool metadata
            use_sudo: Whether to use sudo
            
        Returns:
            True if successful, False otherwise
        """
        if not tool.installation or not tool.installation.package:
            return False
        
        cmd = ["snap", "install", tool.installation.package]
        if use_sudo:
            cmd.insert(0, "sudo")
        
        result = await self._run_command(cmd)
        return result.returncode == 0
    
    async def _install_manual(self, tool: ToolMetadata, use_sudo: bool) -> bool:
        """Manual installation (placeholder).
        
        Args:
            tool: Tool metadata
            use_sudo: Whether to use sudo
            
        Returns:
            False (manual installation requires user intervention)
        """
        return False
    
    async def _run_command(self, command: list, timeout: int = 300) -> subprocess.CompletedProcess:
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
