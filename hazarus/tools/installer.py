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
import logging
import traceback
from enum import Enum
from typing import Optional, Dict, List, Tuple, Type, Any
from pathlib import Path
from .registry import ToolRegistry, ToolMetadata, ToolStatus, InstallationType
from .detector import ToolDetector

# Configure logging
logger = logging.getLogger(__name__)


def setup_debug_logger() -> logging.Logger:
    """Setup a debug logger for installation operations.
    
    Returns:
        Configured logger instance
    """
    debug_logger = logging.getLogger("hazarus.installer.debug")
    debug_logger.setLevel(logging.DEBUG)
    
    # Avoid adding duplicate handlers
    if not debug_logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        debug_logger.addHandler(handler)
    
    return debug_logger


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
    
    async def install_tool(self, tool_name: str, sudo: bool = None, debug: bool = None) -> ToolStatus:
        """Install a single tool with fallback methods.
        
        Args:
            tool_name: Name of the tool to install
            sudo: Whether to use sudo (None = auto-detect based on tool config)
            debug: Enable debug logging (None = use instance default)
            
        Returns:
            ToolStatus after installation attempt
        """
        # Use instance debug setting if not overridden
        use_debug = debug if debug is not None else self.debug
        
        if use_debug and self.debug_logger:
            self.debug_logger.info("=" * 80)
            self.debug_logger.info(f"Starting installation of tool: {tool_name}")
            self.debug_logger.info(f"Sudo: {sudo}, Debug: {use_debug}")
            self.debug_logger.info("=" * 80)
        
        tool = self.registry.get_tool(tool_name)
        if not tool:
            if use_debug and self.debug_logger:
                self.debug_logger.error(f"Tool not found in registry: {tool_name}")
            return ToolStatus(
                name=tool_name,
                installed=False,
                compatible=False,
                compatible_reason="Tool not found in registry",
                error_code=InstallationErrorCode.TOOL_NOT_FOUND.value
            )
        
        if not tool.installation:
            if use_debug and self.debug_logger:
                self.debug_logger.error(f"No installation configuration for: {tool_name}")
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
            if use_debug and self.debug_logger:
                self.debug_logger.error(f"Platform incompatibility for {tool_name}: {platform_reason}")
            return ToolStatus(
                name=tool_name,
                installed=False,
                compatible=False,
                compatible_reason=platform_reason
            )
        
        # Determine sudo requirement
        use_sudo = sudo if sudo is not None else tool.installation.sudo_required
        
        if use_debug and self.debug_logger:
            self.debug_logger.info(f"Installation type: {tool.installation.type.value}")
            self.debug_logger.info(f"Use sudo: {use_sudo}")
            self.debug_logger.info(f"Package: {tool.installation.package}")
            if tool.installation.repo:
                self.debug_logger.info(f"GitHub repo: {tool.installation.repo}")
        
        # Check if already installed
        current_status = await self.detector.check_tool(tool_name)
        if current_status.installed:
            if use_debug and self.debug_logger:
                self.debug_logger.info(f"Tool {tool_name} already installed")
            return current_status
        
        # Build list of installation methods to try (primary + fallbacks)
        installation_methods = [tool.installation.type] + tool.installation.fallback_methods
        
        if use_debug and self.debug_logger:
            self.debug_logger.info(f"Installation methods to try: {[m.value for m in installation_methods]}")
        
        last_error = None
        last_error_code = None
        
        # Try each installation method in order
        for install_type in installation_methods:
            installer_func = self.installers.get(install_type)
            if not installer_func:
                print(f"  Skipping unsupported installation type: {install_type}")
                if use_debug and self.debug_logger:
                    self.debug_logger.warning(f"Unsupported installation type: {install_type.value}")
                continue
            
            print(f"  Attempting installation via {install_type.value}...")
            if use_debug and self.debug_logger:
                self.debug_logger.info(f"Attempting installation via {install_type.value}")
            
            try:
                success = await installer_func(tool, use_sudo, debug=use_debug)
                
                if success:
                    # Verify installation
                    new_status = await self.detector.check_tool(tool_name)
                    # Update status with the successful installation method
                    new_status.installation_method = install_type
                    print(f"  Successfully installed {tool_name} via {install_type.value}")
                    if use_debug and self.debug_logger:
                        self.debug_logger.info(f"Successfully installed {tool_name} via {install_type.value}")
                        self.debug_logger.info(f"Installation verified: {new_status.installed}")
                    return new_status
                else:
                    print(f"  Installation via {install_type.value} failed")
                    last_error = f"Installation via {install_type.value} failed"
                    last_error_code = InstallationErrorCode.INSTALLATION_FAILED.value
                    if use_debug and self.debug_logger:
                        self.debug_logger.error(f"Installation via {install_type.value} failed")
            except PermissionError as e:
                print(f"  Permission denied via {install_type.value}: {str(e)}")
                last_error = f"Permission denied: {str(e)}. Try with sudo."
                last_error_code = InstallationErrorCode.PERMISSION_DENIED.value
                if use_debug and self.debug_logger:
                    self.debug_logger.error(f"Permission denied via {install_type.value}: {str(e)}")
                    self.debug_logger.debug(traceback.format_exc())
            except FileNotFoundError as e:
                print(f"  Dependency missing via {install_type.value}: {str(e)}")
                last_error = f"Required tool or file not found: {str(e)}"
                last_error_code = InstallationErrorCode.DEPENDENCY_MISSING.value
                if use_debug and self.debug_logger:
                    self.debug_logger.error(f"Dependency missing via {install_type.value}: {str(e)}")
                    self.debug_logger.debug(traceback.format_exc())
            except TimeoutError as e:
                print(f"  Timeout via {install_type.value}: {str(e)}")
                last_error = f"Installation timed out: {str(e)}"
                last_error_code = InstallationErrorCode.TIMEOUT.value
                if use_debug and self.debug_logger:
                    self.debug_logger.error(f"Timeout via {install_type.value}: {str(e)}")
                    self.debug_logger.debug(traceback.format_exc())
            except ConnectionError as e:
                print(f"  Network error via {install_type.value}: {str(e)}")
                last_error = f"Network error during installation: {str(e)}"
                last_error_code = InstallationErrorCode.NETWORK_ERROR.value
                if use_debug and self.debug_logger:
                    self.debug_logger.error(f"Network error via {install_type.value}: {str(e)}")
                    self.debug_logger.debug(traceback.format_exc())
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
                if use_debug and self.debug_logger:
                    self.debug_logger.error(f"OSError via {install_type.value}: {str(e)}")
                    self.debug_logger.debug(traceback.format_exc())
            except Exception as e:
                print(f"  Unexpected error via {install_type.value}: {str(e)}")
                last_error = f"Unexpected installation error: {str(e)}"
                last_error_code = InstallationErrorCode.UNKNOWN_ERROR.value
                if use_debug and self.debug_logger:
                    self.debug_logger.error(f"Unexpected error via {install_type.value}: {str(e)}")
                    self.debug_logger.debug(traceback.format_exc())
        
        # All methods failed
        if use_debug and self.debug_logger:
            self.debug_logger.error(f"All installation methods failed for {tool_name}")
            self.debug_logger.error(f"Last error: {last_error}")
            self.debug_logger.error(f"Last error code: {last_error_code}")
        
        return ToolStatus(
            name=tool_name,
            installed=False,
            compatible=False,
            compatible_reason=last_error or "All installation methods failed",
            error_code=last_error_code or InstallationErrorCode.INSTALLATION_FAILED.value
        )
    
    async def install_all_missing(self, sudo: bool = None, debug: bool = None) -> Dict[str, ToolStatus]:
        """Install all missing tools.
        
        Args:
            sudo: Whether to use sudo (None = auto-detect)
            debug: Enable debug logging (None = use instance default)
            
        Returns:
            Dictionary mapping tool names to installation status
        """
        use_debug = debug if debug is not None else self.debug
        
        if use_debug and self.debug_logger:
            self.debug_logger.info("=" * 80)
            self.debug_logger.info("Starting installation of all missing tools")
            self.debug_logger.info("=" * 80)
        
        missing = await self.detector.check_missing_tools()
        results = {}
        
        if use_debug and self.debug_logger:
            self.debug_logger.info(f"Found {len(missing)} missing tools")
        
        for tool_name in missing.keys():
            results[tool_name] = await self.install_tool(tool_name, sudo, debug=use_debug)
        
        if use_debug and self.debug_logger:
            installed = sum(1 for s in results.values() if s.installed)
            self.debug_logger.info(f"Installation complete: {installed}/{len(results)} tools installed")
            self.debug_logger.info("=" * 80)
        
        return results
    
    async def install_required(self, sudo: bool = None, debug: bool = None) -> Dict[str, ToolStatus]:
        """Install only required tools.
        
        Args:
            sudo: Whether to use sudo (None = auto-detect)
            debug: Enable debug logging (None = use instance default)
            
        Returns:
            Dictionary mapping tool names to installation status
        """
        use_debug = debug if debug is not None else self.debug
        
        if use_debug and self.debug_logger:
            self.debug_logger.info("=" * 80)
            self.debug_logger.info("Starting installation of required tools")
            self.debug_logger.info("=" * 80)
        
        required_tools = self.registry.get_required_tools()
        results = {}
        
        if use_debug and self.debug_logger:
            self.debug_logger.info(f"Found {len(required_tools)} required tools")
        
        for tool_name in required_tools.keys():
            status = await self.detector.check_tool(tool_name)
            if not status.installed:
                results[tool_name] = await self.install_tool(tool_name, sudo, debug=use_debug)
            else:
                results[tool_name] = status
        
        if use_debug and self.debug_logger:
            installed = sum(1 for s in results.values() if s.installed)
            self.debug_logger.info(f"Installation complete: {installed}/{len(results)} required tools installed")
            self.debug_logger.info("=" * 80)
        
        return results
    
    def _is_apt_update_recent(self, max_age_hours: int = 1) -> bool:
        """Check if apt update was run recently.
        
        Args:
            max_age_hours: Maximum age in hours to consider recent
            
        Returns:
            True if apt update was run within max_age_hours
        """
        try:
            # Check the timestamp of /var/lib/apt/lists
            apt_lists_dir = Path("/var/lib/apt/lists")
            if not apt_lists_dir.exists():
                return False
            
            # Get the most recent modification time
            stat_info = apt_lists_dir.stat()
            mtime = stat_info.st_mtime
            current_time = time.time()
            age_hours = (current_time - mtime) / 3600
            
            if age_hours < max_age_hours:
                logger.debug(f"APT update was run {age_hours:.1f} hours ago (recent)")
                return True
            
            logger.debug(f"APT update was run {age_hours:.1f} hours ago (not recent)")
            return False
        except Exception as e:
            logger.debug(f"Could not check apt update age: {e}")
            return False
    
    async def _wait_for_apt_lock(self, max_wait_seconds: int = 120) -> bool:
        """Wait for APT lock to be released.
        
        Args:
            max_wait_seconds: Maximum time to wait for lock
            
        Returns:
            True if lock was released, False if timeout
        """
        lock_files = [
            "/var/lib/dpkg/lock-frontend",
            "/var/lib/dpkg/lock",
            "/var/lib/apt/lists/lock",
            "/var/cache/apt/archives/lock"
        ]
        
        start_time = time.time()
        
        while time.time() - start_time < max_wait_seconds:
            locked = False
            for lock_file in lock_files:
                if Path(lock_file).exists():
                    try:
                        # Try to open the file exclusively to check if it's locked
                        with open(lock_file, 'r') as f:
                            pass
                    except (IOError, PermissionError):
                        locked = True
                        break
            
            if not locked:
                logger.debug("APT locks are free")
                return True
            
            logger.debug(f"APT locks are held, waiting... ({int(time.time() - start_time)}s)")
            await asyncio.sleep(2)
        
        logger.warning(f"APT lock wait timeout after {max_wait_seconds}s")
        return False
    
    async def _install_apt(self, tool: ToolMetadata, use_sudo: bool) -> bool:
        """Install tool via APT package manager with retry logic and timeout handling.
        
        Args:
            tool: Tool metadata
            use_sudo: Whether to use sudo
            debug: Enable debug logging
            
        Returns:
            True if successful, False otherwise
            
        Raises:
            PermissionError: If sudo is required but not provided
            FileNotFoundError: If apt is not available
            subprocess.SubprocessError: If apt command fails
        """
        if not tool.installation or not tool.installation.package:
            raise ValueError("Package name not specified in tool configuration")
        
        debug_logger = self.debug_logger if debug else None
        
        if debug and debug_logger:
            debug_logger.info(f"Starting APT installation for {tool.name}")
            debug_logger.info(f"Package: {tool.installation.package}")
            debug_logger.info(f"Use sudo: {use_sudo}")
        
        # Increased timeout for APT operations (600 seconds = 10 minutes)
        APT_TIMEOUT = 600
        
        # Update package list with retry - skip if recently run
        async def _update_package_list():
            # Skip update if it was run recently (within 1 hour)
            if self._is_apt_update_recent(max_age_hours=1):
                logger.info("Skipping APT update (recently run)")
                print("  Skipping APT update (recently run)")
                if debug and debug_logger:
                    debug_logger.info("Skipping APT update (recently run)")
                return None
            
            # Wait for APT lock before updating
            if not await self._wait_for_apt_lock(max_wait_seconds=120):
                print("  Warning: Could not acquire APT lock, attempting update anyway")
                if debug and debug_logger:
                    debug_logger.warning("Could not acquire APT lock, attempting update anyway")
            
            cmd = ["apt", "update"]
            if use_sudo:
                cmd.insert(0, "sudo")
            
            logger.debug(f"Running APT update: {' '.join(cmd)}")
            print(f"  Running: {' '.join(cmd)}")
            
            if debug and debug_logger:
                debug_logger.info(f"Executing command: {' '.join(cmd)}")
            
            result = await self._run_command(cmd, timeout=APT_TIMEOUT, debug=debug)
            
            if debug and debug_logger:
                debug_logger.info(f"Command return code: {result.returncode}")
                if result.stdout:
                    debug_logger.debug(f"STDOUT:\n{result.stdout}")
                if result.stderr:
                    debug_logger.debug(f"STDERR:\n{result.stderr}")
            
            if result.returncode != 0:
                stderr = result.stderr.strip()
                # Check if it's a partial failure that we can ignore
                if "Some index files failed to download" in stderr or "Release file" in stderr:
                    logger.warning(f"APT update had partial failures, continuing: {stderr}")
                    print(f"  Warning: APT update had partial failures, continuing")
                    if debug and debug_logger:
                        debug_logger.warning(f"APT update had partial failures, continuing")
                    return None
                raise subprocess.SubprocessError(
                    f"APT update failed: {stderr}"
                )
            logger.debug("APT update successful")
            if debug and debug_logger:
                debug_logger.info("APT update successful")
            return result
        
        try:
            await retry_command_with_backoff(_update_package_list, max_retries=3, debug=debug)
        except FileNotFoundError:
            if debug and debug_logger:
                debug_logger.error("APT package manager not found")
            raise FileNotFoundError("APT package manager not found. This system may not use APT.")
        except PermissionError:
            if debug and debug_logger:
                debug_logger.error("Permission denied updating APT packages")
            raise PermissionError("Permission denied updating APT packages. Try with sudo.")
        except Exception as e:
            logger.warning(f"APT update failed after retries: {e}")
            print(f"  Warning: APT update failed after retries: {e}")
            if debug and debug_logger:
                debug_logger.error(f"APT update failed after retries: {e}")
                debug_logger.debug(traceback.format_exc())
            # Continue with installation attempt even if update failed
        
        # Install package with retry
        async def _install_package():
            # Wait for APT lock before installing
            if not await self._wait_for_apt_lock(max_wait_seconds=120):
                print("  Warning: Could not acquire APT lock, attempting installation anyway")
                if debug and debug_logger:
                    debug_logger.warning("Could not acquire APT lock, attempting installation anyway")
            
            # Add --allow-downgrades for compatibility and -qq for quieter output
            cmd = ["apt", "install", "-y", "--allow-downgrades", tool.installation.package]
            if use_sudo:
                cmd.insert(0, "sudo")
            
            logger.debug(f"Running APT install: {' '.join(cmd)}")
            print(f"  Running: {' '.join(cmd)}")
            
            if debug and debug_logger:
                debug_logger.info(f"Executing command: {' '.join(cmd)}")
            
            result = await self._run_command(cmd, timeout=APT_TIMEOUT, debug=debug)
            
            if debug and debug_logger:
                debug_logger.info(f"Command return code: {result.returncode}")
                if result.stdout:
                    debug_logger.debug(f"STDOUT:\n{result.stdout}")
                if result.stderr:
                    debug_logger.debug(f"STDERR:\n{result.stderr}")
            
            if result.returncode != 0:
                stderr = result.stderr.strip()
                stdout = result.stdout.strip()
                
                # Provide detailed error messages
                if "E: Unable to locate package" in stderr:
                    error_msg = (
                        f"Package '{tool.installation.package}' not found in APT repositories. "
                        f"This may be due to missing sources or incompatible distribution."
                    )
                    logger.error(error_msg)
                    if debug and debug_logger:
                        debug_logger.error(error_msg)
                    raise ValueError(error_msg)
                elif "E: Could not get lock" in stderr or "dpkg frontend is locked" in stderr:
                    error_msg = (
                        "Another APT process is running (lock conflict). "
                        "Wait for other package operations to complete or try: sudo rm /var/lib/dpkg/lock-frontend"
                    )
                    logger.error(error_msg)
                    if debug and debug_logger:
                        debug_logger.error(error_msg)
                    raise PermissionError(error_msg)
                elif "E: Unable to correct missing dependencies" in stderr:
                    error_msg = (
                        f"Dependency resolution failed for '{tool.installation.package}'. "
                        "This may require manual intervention or system updates."
                    )
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                elif "E: Package is in a very bad inconsistent state" in stderr:
                    error_msg = (
                        f"Package '{tool.installation.package}' is in a bad state. "
                        "Try: sudo dpkg --configure -a && sudo apt install -f"
                    )
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                else:
                    error_msg = f"APT install failed: {stderr}"
                    if stdout:
                        error_msg += f"\nOutput: {stdout}"
                    logger.error(error_msg)
                    raise subprocess.SubprocessError(error_msg)
            
            logger.debug(f"APT install successful for {tool.installation.package}")
            return result
        
        try:
            result = await retry_command_with_backoff(_install_package, max_retries=3)
            return True
        except PermissionError:
            raise PermissionError("Permission denied installing APT package. Try with sudo.")
        except Exception as e:
            logger.error(f"APT install failed after retries: {e}")
            print(f"  APT install failed after retries: {e}")
            return False
    
    def _is_package_installed(self, package_name: str) -> tuple[bool, str]:
        """Check if a Python package is already installed.
        
        Args:
            package_name: Name of the package to check
            
        Returns:
            Tuple of (is_installed, installation_method)
            installation_method can be 'pip', 'system', or 'not_installed'
        """
        try:
            # Try to import the package to check if it's installed
            import importlib.metadata
            try:
                dist = importlib.metadata.distribution(package_name)
                # Check if it has a RECORD file (indicates pip installation)
                try:
                    dist.read_text('RECORD')
                    return True, 'pip'
                except (FileNotFoundError, KeyError):
                    # No RECORD file, likely installed by system package manager
                    return True, 'system'
            except importlib.metadata.PackageNotFoundError:
                return False, 'not_installed'
        except Exception:
            # Fallback: try pip show
            try:
                result = subprocess.run(
                    ['pip', 'show', package_name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    # Package is installed via pip
                    return True, 'pip'
                else:
                    # Not installed via pip, check if system package
                    # Check common Debian packages
                    deb_packages = {
                        'typing_extensions': 'python3-typing-extensions',
                        'cryptography': 'python3-cryptography',
                        'requests': 'python3-requests',
                        'urllib3': 'python3-urllib3',
                        'certifi': 'python3-certifi',
                        'charset-normalizer': 'python3-charmap-normalizer',
                        'idna': 'python3-idna',
                        'beautifulsoup4': 'python3-bs4',
                        'lxml': 'python3-lxml',
                        'yaml': 'python3-yaml',
                        'jinja2': 'python3-jinja2',
                        'markupsafe': 'python3-markupsafe',
                        'click': 'python3-click',
                        'pydantic': 'python3-pydantic',
                        'typer': 'python3-typer',
                        'rich': 'python3-rich',
                        'httpx': 'python3-httpx',
                        'dnspython': 'python3-dnspython',
                    }
                    deb_pkg = deb_packages.get(package_name)
                    if deb_pkg:
                        result = subprocess.run(
                            ['dpkg', '-l', deb_pkg],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        if result.returncode == 0 and 'ii' in result.stdout:
                            return True, 'system'
                    return False, 'not_installed'
            except Exception:
                return False, 'not_installed'
    
    def _get_python_version(self) -> tuple[int, int, int]:
        """Get the current Python version.
        
        Returns:
            Tuple of (major, minor, patch)
        """
        import sys
        return sys.version_info[:3]
    
    def _needs_break_system_packages(self) -> bool:
        """Check if --break-system-packages flag is needed.
        
        Returns:
            True if Python 3.13+ or flag is needed
        """
        major, minor, _ = self._get_python_version()
        # Python 3.13+ requires --break-system-packages for system installs
        if major > 3 or (major == 3 and minor >= 13):
            return True
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
        
        package_name = tool.installation.package
        
        # Check if package is already installed
        is_installed, install_method = self._is_package_installed(package_name)
        if is_installed:
            if install_method == 'system':
                print(f"  Package '{package_name}' is already installed by system package manager")
                print(f"  Skipping pip installation to avoid conflicts")
                return True
            elif install_method == 'pip':
                print(f"  Package '{package_name}' is already installed via pip")
                print(f"  Skipping installation")
                return True
        
        # Determine if we need --break-system-packages
        needs_break_flag = self._needs_break_system_packages()
        
        # Build pip install command with appropriate flags
        def build_pip_command(user_install: bool = False) -> list:
            """Build pip install command with appropriate flags."""
            cmd = ["pip", "install"]
            
            # Add --skip-existing to avoid upgrading already installed packages
            cmd.append("--skip-existing")
            
            # Add --break-system-packages only if needed (Python 3.13+)
            if needs_break_flag and not user_install:
                cmd.append("--break-system-packages")
            
            # Add --user flag for user-space installation
            if user_install:
                cmd.append("--user")
            
            # Add the package name
            cmd.append(package_name)
            
            return cmd
        
        # Install package with retry for network errors
        async def _install_package_with_method(method_name: str, cmd: list) -> bool:
            """Install package using a specific method."""
            print(f"  Attempting pip install via {method_name}...")
            print(f"  Command: {' '.join(cmd)}")
            
            result = await self._run_command(cmd)
            
            if result.returncode != 0:
                stderr = result.stderr.strip()
                stdout = result.stdout.strip()
                
                if "command not found" in stderr.lower() or "No such file" in stderr:
                    raise FileNotFoundError("Pip is not installed or not in PATH")
                elif "Permission denied" in stderr or "Access is denied" in stderr:
                    raise PermissionError("Permission denied installing pip package. Try with sudo.")
                elif "Could not find a version" in stderr or "No matching distribution" in stderr:
                    raise ValueError(f"Package '{package_name}' not found on PyPI")
                elif "already satisfied" in stderr or "Requirement already satisfied" in stdout:
                    # Package already installed, consider this a success
                    print(f"  Package '{package_name}' is already satisfied")
                    return True
                elif "uninstall-no-record-file" in stderr:
                    # Debian package conflict - package was installed by system
                    print(f"  Detected Debian package conflict for '{package_name}'")
                    print(f"  Package is installed by system package manager")
                    return True  # Consider this a success since package is available
                elif "externally-managed-environment" in stderr:
                    # Python 3.11+ externally managed environment
                    print(f"  Detected externally managed Python environment")
                    raise PermissionError("System Python is externally managed. Use --user flag or --break-system-packages")
                elif "Network is unreachable" in stderr or "Connection error" in stderr or "Timeout" in stderr:
                    # Network error - should retry
                    raise ConnectionError(f"Network error during pip install: {stderr}")
                elif "Consider using the `--user` option" in stderr:
                    # Suggests using --user flag
                    raise PermissionError("Permission denied. Try using --user flag or sudo")
                else:
                    # Generic error with details
                    error_msg = f"Pip install failed via {method_name}"
                    if stderr:
                        error_msg += f": {stderr}"
                    if stdout:
                        error_msg += f" (stdout: {stdout})"
                    raise subprocess.SubprocessError(error_msg)
            
            print(f"  Successfully installed '{package_name}' via {method_name}")
            return True
        
        # Try different installation methods in order
        installation_methods = []
        
        if use_sudo:
            # Method 1: System-wide install with sudo
            installation_methods.append(("system-wide with sudo", build_pip_command(user_install=False), True))
        
        # Method 2: System-wide install without sudo (if not using sudo)
        if not use_sudo:
            installation_methods.append(("system-wide without sudo", build_pip_command(user_install=False), False))
        
        # Method 3: User-space install (fallback)
        installation_methods.append(("user-space", build_pip_command(user_install=True), False))
        
        # Method 4: System-wide with --break-system-packages (if needed and not already tried)
        if needs_break_flag and not use_sudo:
            cmd = ["pip", "install", "--break-system-packages", "--skip-existing", package_name]
            installation_methods.append(("system-wide with --break-system-packages", cmd, False))
        
        last_error = None
        
        for method_name, cmd, needs_sudo in installation_methods:
            if needs_sudo and not use_sudo:
                continue
            
            try:
                # Add sudo if needed
                final_cmd = cmd.copy()
                if needs_sudo:
                    final_cmd.insert(0, "sudo")
                
                result = await retry_command_with_backoff(
                    lambda: _install_package_with_method(method_name, final_cmd),
                    max_retries=3
                )
                return result
            except FileNotFoundError:
                raise FileNotFoundError("Pip is not installed or not in PATH")
            except PermissionError as e:
                last_error = str(e)
                print(f"  {method_name} failed: {e}")
                continue  # Try next method
            except ValueError:
                # Package not found - don't retry other methods
                raise
            except ConnectionError as e:
                last_error = str(e)
                print(f"  {method_name} failed due to network error: {e}")
                continue  # Try next method
            except subprocess.SubprocessError as e:
                last_error = str(e)
                print(f"  {method_name} failed: {e}")
                continue  # Try next method
            except Exception as e:
                last_error = str(e)
                print(f"  {method_name} failed with unexpected error: {e}")
                continue  # Try next method
        
        # All methods failed
        if last_error:
            raise subprocess.SubprocessError(f"All pip installation methods failed. Last error: {last_error}")
        return False
    
    async def _install_github(self, tool: ToolMetadata, use_sudo: bool) -> bool:
        """Install tool from GitHub releases.
        
        Args:
            tool: Tool metadata
            use_sudo: Whether to use sudo
            debug: Enable debug logging
            
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
        
        debug_logger = self.debug_logger if debug else None
        
        if debug and debug_logger:
            debug_logger.info(f"Starting GitHub installation for {tool.name}")
            debug_logger.info(f"Repository: {tool.installation.repo}")
            debug_logger.info(f"Asset pattern: {tool.installation.asset_pattern}")
            debug_logger.info(f"Use sudo: {use_sudo}")
        
        try:
            from .downloader import GitHubDownloader
            
            downloader = GitHubDownloader(debug=debug)
            
            # Download asset
            print(f"  Downloading {tool.name} from GitHub...")
            if debug and debug_logger:
                debug_logger.info(f"Downloading {tool.name} from GitHub releases")
            
            asset_path = await downloader.download_latest_release(
                tool.installation.repo,
                tool.installation.asset_pattern
            )
            
            if not asset_path:
                if debug and debug_logger:
                    debug_logger.error(f"Failed to download {tool.name} from GitHub releases")
                raise ConnectionError(f"Failed to download {tool.name} from GitHub releases")
            
            if debug and debug_logger:
                debug_logger.info(f"Downloaded asset to: {asset_path}")
            
            print(f"  Extracting {tool.name}...")
            if debug and debug_logger:
                debug_logger.info(f"Extracting archive: {asset_path}")
            
            # Extract
            extract_dir = await downloader.extract_archive(asset_path)
            
            if not extract_dir:
                if debug and debug_logger:
                    debug_logger.error(f"Failed to extract {tool.name} archive")
                raise OSError(f"Failed to extract {tool.name} archive")
            
            if debug and debug_logger:
                debug_logger.info(f"Extracted to: {extract_dir}")
            
            # Install
            install_path = tool.installation.install_path or "/usr/local/bin"
            
            if debug and debug_logger:
                debug_logger.info(f"Install path: {install_path}")
            
            if use_sudo:
                # System-wide install
                install_path = tool.installation.install_path or "/usr/local/bin"
                
                # Find all executable files recursively
                executables = []
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        file_path = Path(root) / file
                        if os.access(file_path, os.X_OK):
                            executables.append(file_path)
                
                if not executables:
                    if debug and debug_logger:
                        debug_logger.error(f"No executable files found in {extract_dir}")
                    raise OSError(f"No executable files found in extracted archive for {tool.name}")
                
                if debug and debug_logger:
                    debug_logger.info(f"Found {len(executables)} executable files")
                    for exe in executables:
                        debug_logger.debug(f"  - {exe}")
                
                # Copy each executable individually
                for exe in executables:
                    cmd = ["sudo", "cp", str(exe), install_path]
                    
                    if debug and debug_logger:
                        debug_logger.info(f"Copying {exe.name} to {install_path}")
                        debug_logger.info(f"Executing command: {' '.join(cmd)}")
                    
                    result = await self._run_command(cmd, debug=debug)
                    
                    if debug and debug_logger:
                        debug_logger.info(f"Command return code: {result.returncode}")
                        if result.stdout:
                            debug_logger.debug(f"STDOUT:\n{result.stdout}")
                        if result.stderr:
                            debug_logger.debug(f"STDERR:\n{result.stderr}")
                    
                    if result.returncode != 0:
                        stderr = result.stderr.strip()
                        if "Permission denied" in stderr:
                            raise PermissionError(f"Permission denied copying {exe.name} to {install_path}. Try with sudo.")
                        else:
                            raise OSError(f"Failed to copy {exe.name} to {install_path}: {stderr}")
            else:
                # User-space install
                install_path = Path.home() / ".local" / "bin"
                try:
                    install_path.mkdir(parents=True, exist_ok=True)
                except PermissionError:
                    raise PermissionError(f"Permission denied creating {install_path}")
                
                # Find all executable files recursively
                executables = []
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        file_path = Path(root) / file
                        if os.access(file_path, os.X_OK):
                            executables.append(file_path)
                
                if not executables:
                    if debug and debug_logger:
                        debug_logger.error(f"No executable files found in {extract_dir}")
                    raise OSError(f"No executable files found in extracted archive for {tool.name}")
                
                if debug and debug_logger:
                    debug_logger.info(f"Found {len(executables)} executable files for user-space install")
                
                # Copy each executable
                for exe in executables:
                    if debug and debug_logger:
                        debug_logger.info(f"Copying {exe.name} to {install_path}")
                    try:
                        shutil.copy(exe, install_path / exe.name)
                    except PermissionError:
                        raise PermissionError(f"Permission denied copying {exe.name} to {install_path}")
            
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
            debug: Enable debug logging
            
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
        
        debug_logger = self.debug_logger if debug else None
        
        if debug and debug_logger:
            debug_logger.info(f"Starting snap installation for {tool.name}")
            debug_logger.info(f"Package: {tool.installation.package}")
            debug_logger.info(f"Use sudo: {use_sudo}")
        
        cmd = ["snap", "install", tool.installation.package]
        if use_sudo:
            cmd.insert(0, "sudo")
        
        if debug and debug_logger:
            debug_logger.info(f"Executing command: {' '.join(cmd)}")
        
        try:
            result = await self._run_command(cmd, debug=debug)
            
            if debug and debug_logger:
                debug_logger.info(f"Command return code: {result.returncode}")
                if result.stdout:
                    debug_logger.debug(f"STDOUT:\n{result.stdout}")
                if result.stderr:
                    debug_logger.debug(f"STDERR:\n{result.stderr}")
            
            if result.returncode != 0:
                stderr = result.stderr.strip()
                if "command not found" in stderr.lower() or "No such file" in stderr:
                    if debug and debug_logger:
                        debug_logger.error("Snap is not installed or not in PATH")
                    raise FileNotFoundError("Snap is not installed or not in PATH")
                elif "Permission denied" in stderr or "Access is denied" in stderr:
                    if debug and debug_logger:
                        debug_logger.error("Permission denied installing snap package")
                    raise PermissionError("Permission denied installing snap package. Try with sudo.")
                elif "snap" in stderr.lower() and "not found" in stderr.lower():
                    if debug and debug_logger:
                        debug_logger.error(f"Snap package '{tool.installation.package}' not found")
                    raise ValueError(f"Snap package '{tool.installation.package}' not found")
                else:
                    if debug and debug_logger:
                        debug_logger.error(f"Snap install failed: {stderr}")
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
            debug: Enable debug logging
            
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
