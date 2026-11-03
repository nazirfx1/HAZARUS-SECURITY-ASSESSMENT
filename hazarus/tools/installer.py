"""
HAZARUS Tool Installer
Automated installation of external security tools.
"""

import asyncio
import os
import platform
import subprocess
import shutil
import time
from enum import Enum
from typing import Optional, Dict, List, Tuple, Type, Any
from pathlib import Path
from .registry import ToolRegistry, ToolMetadata, ToolStatus, InstallationType
from .detector import ToolDetector


# Network-related errors that should trigger retry for package installations
RETRYABLE_INSTALL_ERRORS = (
    subprocess.TimeoutExpired,
    ConnectionError,
    TimeoutError,
)


async def retry_command_with_backoff(
    command_func: callable,
    *args,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    retryable_errors: Tuple[Type[Exception], ...] = RETRYABLE_INSTALL_ERRORS,
    **kwargs
) -> Any:
    """Execute command function with exponential backoff retry logic.
    
    Args:
        command_func: Async function to execute
        *args: Positional arguments for func
        max_retries: Maximum number of retry attempts (default 3)
        base_delay: Base delay in seconds (default 1.0)
        max_delay: Maximum delay in seconds (default 60.0)
        retryable_errors: Tuple of exception types to retry on
        **kwargs: Keyword arguments for func
        
    Returns:
        Function result
        
    Raises:
        Last exception if all retries exhausted
    """
    last_exception = None
    
    for attempt in range(max_retries + 1):
        try:
            return await command_func(*args, **kwargs)
        except retryable_errors as e:
            last_exception = e
            if attempt < max_retries:
                delay = min(base_delay * (2 ** attempt), max_delay)
                print(f"  Retry {attempt + 1}/{max_retries} after {delay:.1f}s ({type(e).__name__})")
                await asyncio.sleep(delay)
            continue
        except Exception as e:
            # Non-retryable exception
            raise
    
    # All retries exhausted
    if last_exception:
        raise last_exception
    raise RuntimeError("All retries exhausted")


class InstallationErrorCode(Enum):
    """Error codes for categorizing installation failures."""
    
    # Network-related errors
    NETWORK_ERROR = "NETWORK_ERROR"
    DOWNLOAD_FAILED = "DOWNLOAD_FAILED"
    TIMEOUT = "TIMEOUT"
    
    # Permission-related errors
    PERMISSION_DENIED = "PERMISSION_DENIED"
    SUDO_REQUIRED = "SUDO_REQUIRED"
    
    # Dependency-related errors
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    PACKAGE_NOT_FOUND = "PACKAGE_NOT_FOUND"
    VERSION_CONFLICT = "VERSION_CONFLICT"
    
    # Configuration errors
    INVALID_CONFIG = "INVALID_CONFIG"
    UNSUPPORTED_INSTALL_TYPE = "UNSUPPORTED_INSTALL_TYPE"
    
    # System errors
    DISK_SPACE = "DISK_SPACE"
    FILESYSTEM_ERROR = "FILESYSTEM_ERROR"
    
    # Tool-specific errors
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    EXTRACTION_FAILED = "EXTRACTION_FAILED"
    INSTALLATION_FAILED = "INSTALLATION_FAILED"
    
    # Unknown errors
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


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
        self.current_platform = self._detect_platform()
    
    def _detect_platform(self) -> str:
        """Detect the current platform.
        
        Returns:
            Platform identifier string
        """
        system = platform.system().lower()
        if system == "linux":
            try:
                with open("/etc/os-release", "r") as f:
                    content = f.read()
                    if "ubuntu" in content.lower():
                        return "ubuntu"
                    elif "debian" in content.lower():
                        return "debian"
                    elif "parrot" in content.lower():
                        return "parrot"
                    elif "kali" in content.lower():
                        return "kali"
                    elif "fedora" in content.lower():
                        return "fedora"
                    elif "arch" in content.lower():
                        return "arch"
            except Exception:
                pass
            return "linux"
        elif system == "darwin":
            return "macos"
        elif system == "windows":
            return "windows"
        return system
    
    def _is_platform_compatible(self, tool: ToolMetadata) -> tuple[bool, Optional[str]]:
        """Check if tool is compatible with current platform.
        
        Args:
            tool: Tool metadata
            
        Returns:
            Tuple of (compatible, reason)
        """
        if not tool.platforms:
            return True, None  # No platform restrictions
        
        if self.current_platform in tool.platforms:
            return True, None
        
        return False, f"Tool not compatible with platform: {self.current_platform} (supported: {', '.join(tool.platforms)})"
    
    async def install_tool(self, tool_name: str, sudo: bool = None) -> ToolStatus:
        """Install a single tool with fallback methods.
        
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
                compatible_reason="Tool not found in registry",
                error_code=InstallationErrorCode.TOOL_NOT_FOUND.value
            )
        
        if not tool.installation:
            return ToolStatus(
                name=tool_name,
                installed=False,
                compatible=False,
                compatible_reason="No installation configuration",
                error_code=InstallationErrorCode.INVALID_CONFIG.value
            )
        
        # Check platform compatibility
        platform_compatible, platform_reason = self._is_platform_compatible(tool)
        if not platform_compatible:
            return ToolStatus(
                name=tool_name,
                installed=False,
                compatible=False,
                compatible_reason=platform_reason
            )
        
        # Determine sudo requirement
        use_sudo = sudo if sudo is not None else tool.installation.sudo_required
        
        # Check if already installed
        current_status = await self.detector.check_tool(tool_name)
        if current_status.installed:
            return current_status
        
        # Build list of installation methods to try (primary + fallbacks)
        installation_methods = [tool.installation.type] + tool.installation.fallback_methods
        
        last_error = None
        last_error_code = None
        
        # Try each installation method in order
        for install_type in installation_methods:
            installer_func = self.installers.get(install_type)
            if not installer_func:
                print(f"  Skipping unsupported installation type: {install_type}")
                continue
            
            print(f"  Attempting installation via {install_type.value}...")
            
            try:
                success = await installer_func(tool, use_sudo)
                
                if success:
                    # Verify installation
                    new_status = await self.detector.check_tool(tool_name)
                    # Update status with the successful installation method
                    new_status.installation_method = install_type
                    print(f"  Successfully installed {tool_name} via {install_type.value}")
                    return new_status
                else:
                    print(f"  Installation via {install_type.value} failed")
                    last_error = f"Installation via {install_type.value} failed"
                    last_error_code = InstallationErrorCode.INSTALLATION_FAILED.value
            except PermissionError as e:
                print(f"  Permission denied via {install_type.value}: {str(e)}")
                last_error = f"Permission denied: {str(e)}. Try with sudo."
                last_error_code = InstallationErrorCode.PERMISSION_DENIED.value
            except FileNotFoundError as e:
                print(f"  Dependency missing via {install_type.value}: {str(e)}")
                last_error = f"Required tool or file not found: {str(e)}"
                last_error_code = InstallationErrorCode.DEPENDENCY_MISSING.value
            except TimeoutError as e:
                print(f"  Timeout via {install_type.value}: {str(e)}")
                last_error = f"Installation timed out: {str(e)}"
                last_error_code = InstallationErrorCode.TIMEOUT.value
            except ConnectionError as e:
                print(f"  Network error via {install_type.value}: {str(e)}")
                last_error = f"Network error during installation: {str(e)}"
                last_error_code = InstallationErrorCode.NETWORK_ERROR.value
            except OSError as e:
                # Handle disk space and filesystem errors
                if "No space left" in str(e):
                    print(f"  Disk space error via {install_type.value}: {str(e)}")
                    last_error = f"Insufficient disk space: {str(e)}"
                    last_error_code = InstallationErrorCode.DISK_SPACE.value
                else:
                    print(f"  Filesystem error via {install_type.value}: {str(e)}")
                    last_error = f"Filesystem error: {str(e)}"
                    last_error_code = InstallationErrorCode.FILESYSTEM_ERROR.value
            except Exception as e:
                print(f"  Unexpected error via {install_type.value}: {str(e)}")
                last_error = f"Unexpected installation error: {str(e)}"
                last_error_code = InstallationErrorCode.UNKNOWN_ERROR.value
        
        # All methods failed
        return ToolStatus(
            name=tool_name,
            installed=False,
            compatible=False,
            compatible_reason=last_error or "All installation methods failed",
            error_code=last_error_code or InstallationErrorCode.INSTALLATION_FAILED.value
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
        """Install tool via APT package manager with retry logic.
        
        Args:
            tool: Tool metadata
            use_sudo: Whether to use sudo
            
        Returns:
            True if successful, False otherwise
            
        Raises:
            PermissionError: If sudo is required but not provided
            FileNotFoundError: If apt is not available
            subprocess.SubprocessError: If apt command fails
        """
        if not tool.installation or not tool.installation.package:
            raise ValueError("Package name not specified in tool configuration")
        
        # Update package list with retry
        async def _update_package_list():
            cmd = ["apt", "update"]
            if use_sudo:
                cmd.insert(0, "sudo")
            result = await self._run_command(cmd)
            if result.returncode != 0:
                raise subprocess.SubprocessError(
                    f"APT update failed: {result.stderr}"
                )
            return result
        
        try:
            await retry_command_with_backoff(_update_package_list, max_retries=3)
        except FileNotFoundError:
            raise FileNotFoundError("APT package manager not found. This system may not use APT.")
        except PermissionError:
            raise PermissionError("Permission denied updating APT packages. Try with sudo.")
        except Exception as e:
            print(f"  APT update failed after retries: {e}")
            return False
        
        # Install package with retry
        async def _install_package():
            cmd = ["apt", "install", "-y", tool.installation.package]
            if use_sudo:
                cmd.insert(0, "sudo")
            result = await self._run_command(cmd)
            if result.returncode != 0:
                stderr = result.stderr.strip()
                if "E: Unable to locate package" in stderr:
                    raise ValueError(f"Package '{tool.installation.package}' not found in APT repositories")
                elif "E: Could not get lock" in stderr:
                    raise PermissionError("Another APT process is running or insufficient permissions")
                else:
                    raise subprocess.SubprocessError(f"APT install failed: {stderr}")
            return result
        
        try:
            result = await retry_command_with_backoff(_install_package, max_retries=3)
            return True
        except PermissionError:
            raise PermissionError("Permission denied installing APT package. Try with sudo.")
        except Exception as e:
            print(f"  APT install failed after retries: {e}")
            return False
    
    async def _install_pip(self, tool: ToolMetadata, use_sudo: bool) -> bool:
        """Install tool via pip with retry logic for network operations.
        
        Args:
            tool: Tool metadata
            use_sudo: Whether to use sudo (for system install)
            
        Returns:
            True if successful, False otherwise
            
        Raises:
            ValueError: If package name not specified
            FileNotFoundError: If pip is not available
            PermissionError: If insufficient permissions
            subprocess.SubprocessError: If pip command fails
        """
        if not tool.installation or not tool.installation.package:
            raise ValueError("Package name not specified in tool configuration")
        
        # Install package with retry for network errors
        async def _install_package():
            # Use pip with --break-system-packages for Python 3.13+
            cmd = ["pip", "install", "--break-system-packages", tool.installation.package]
            
            if use_sudo:
                # System-wide install
                cmd.insert(0, "sudo")
            
            result = await self._run_command(cmd)
            
            if result.returncode != 0:
                stderr = result.stderr.strip()
                if "command not found" in stderr.lower() or "No such file" in stderr:
                    raise FileNotFoundError("Pip is not installed or not in PATH")
                elif "Permission denied" in stderr or "Access is denied" in stderr:
                    raise PermissionError("Permission denied installing pip package. Try with sudo.")
                elif "Could not find a version" in stderr:
                    raise ValueError(f"Package '{tool.installation.package}' not found on PyPI")
                elif "already satisfied" in stderr:
                    # Package already installed, consider this a success
                    return True
                elif "Network is unreachable" in stderr or "Connection error" in stderr or "Timeout" in stderr:
                    # Network error - should retry
                    raise ConnectionError(f"Network error during pip install: {stderr}")
                else:
                    raise subprocess.SubprocessError(f"Pip install failed: {stderr}")
            
            return True
        
        try:
            result = await retry_command_with_backoff(_install_package, max_retries=3)
            return result
        except FileNotFoundError:
            raise FileNotFoundError("Pip is not installed or not in PATH")
        except PermissionError:
            raise PermissionError("Permission denied installing pip package. Try with sudo.")
        except ValueError:
            # Package not found - don't retry
            raise
        except Exception as e:
            print(f"  Pip install failed after retries: {e}")
            return False
    
    async def _install_github(self, tool: ToolMetadata, use_sudo: bool) -> bool:
        """Install tool from GitHub releases.
        
        Args:
            tool: Tool metadata
            use_sudo: Whether to use sudo
            
        Returns:
            True if successful, False otherwise
            
        Raises:
            ValueError: If repo not specified
            ConnectionError: If download fails
            PermissionError: If insufficient permissions
            OSError: If extraction or installation fails
        """
        if not tool.installation or not tool.installation.repo:
            raise ValueError("GitHub repository not specified in tool configuration")
        
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
                raise ConnectionError(f"Failed to download {tool.name} from GitHub releases")
            
            print(f"  Extracting {tool.name}...")
            # Extract
            extract_dir = await downloader.extract_archive(asset_path)
            
            if not extract_dir:
                raise OSError(f"Failed to extract {tool.name} archive")
            
            # Install
            install_path = tool.installation.install_path or "/usr/local/bin"
            
            if use_sudo:
                # System-wide install
                install_path = tool.installation.install_path or "/usr/local/bin"
                cmd = ["sudo", "cp", "-r", f"{extract_dir}/*", install_path]
                result = await self._run_command(cmd)
                if result.returncode != 0:
                    stderr = result.stderr.strip()
                    if "Permission denied" in stderr:
                        raise PermissionError(f"Permission denied copying to {install_path}. Try with sudo.")
                    else:
                        raise OSError(f"Failed to copy files to {install_path}: {stderr}")
            else:
                # User-space install
                install_path = Path.home() / ".local" / "bin"
                try:
                    install_path.mkdir(parents=True, exist_ok=True)
                except PermissionError:
                    raise PermissionError(f"Permission denied creating {install_path}")
                
                # Copy binaries
                copied = False
                for file in Path(extract_dir).glob("*"):
                    if file.is_file() and os.access(file, os.X_OK):
                        try:
                            shutil.copy(file, install_path / file.name)
                            copied = True
                        except PermissionError:
                            raise PermissionError(f"Permission denied copying {file.name} to {install_path}")
                
                if not copied:
                    raise OSError(f"No executable files found in extracted archive for {tool.name}")
            
            # Cleanup
            shutil.rmtree(asset_path.parent, ignore_errors=True)
            
            return True
            
        except ConnectionError as e:
            raise ConnectionError(f"Network error downloading from GitHub: {str(e)}")
        except PermissionError:
            raise
        except OSError as e:
            if "No space left" in str(e):
                raise OSError(f"Insufficient disk space for {tool.name}: {str(e)}")
            raise OSError(f"Filesystem error during installation: {str(e)}")
    
    async def _install_snap(self, tool: ToolMetadata, use_sudo: bool) -> bool:
        """Install tool via Snap.
        
        Args:
            tool: Tool metadata
            use_sudo: Whether to use sudo
            
        Returns:
            True if successful, False otherwise
            
        Raises:
            ValueError: If package not specified
            FileNotFoundError: If snap is not available
            PermissionError: If insufficient permissions
            subprocess.SubprocessError: If snap command fails
        """
        if not tool.installation or not tool.installation.package:
            raise ValueError("Snap package name not specified in tool configuration")
        
        cmd = ["snap", "install", tool.installation.package]
        if use_sudo:
            cmd.insert(0, "sudo")
        
        try:
            result = await self._run_command(cmd)
            if result.returncode != 0:
                stderr = result.stderr.strip()
                if "command not found" in stderr.lower() or "No such file" in stderr:
                    raise FileNotFoundError("Snap is not installed or not in PATH")
                elif "Permission denied" in stderr or "Access is denied" in stderr:
                    raise PermissionError("Permission denied installing snap package. Try with sudo.")
                elif "snap" in stderr.lower() and "not found" in stderr.lower():
                    raise ValueError(f"Snap package '{tool.installation.package}' not found")
                else:
                    raise subprocess.SubprocessError(f"Snap install failed: {stderr}")
            return True
        except FileNotFoundError:
            raise FileNotFoundError("Snap is not installed or not in PATH")
        except PermissionError:
            raise PermissionError("Permission denied installing snap package. Try with sudo.")
    
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
