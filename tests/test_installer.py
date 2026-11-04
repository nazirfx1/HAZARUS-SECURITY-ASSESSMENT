"""
Tests for the HAZARUS Tool Installer.
"""

import pytest
import subprocess
from unittest.mock import Mock, patch, MagicMock, AsyncMock, mock_open
from hazarus.tools.installer import ToolInstaller, InstallationErrorCode
from hazarus.tools.registry import ToolRegistry, ToolMetadata, InstallationType, ToolCategory, ToolInstallation


@pytest.fixture
def tool_registry():
    """Create a tool registry for testing."""
    return ToolRegistry()


@pytest.fixture
def tool_installer(tool_registry):
    """Create a tool installer for testing."""
    return ToolInstaller(tool_registry)


class TestPackageInstallationDetection:
    """Tests for package installation detection."""
    
    def test_is_package_installed_pip(self, tool_installer):
        """Test detection of pip-installed packages."""
        with patch('importlib.metadata.distribution') as mock_dist:
            mock_dist_obj = Mock()
            mock_dist_obj.read_text.return_value = "file,hash\n"
            mock_dist.return_value = mock_dist_obj
            
            is_installed, method = tool_installer._is_package_installed('requests')
            assert is_installed is True
            assert method == 'pip'
    
    def test_is_package_installed_system(self, tool_installer):
        """Test detection of system-installed packages."""
        with patch('importlib.metadata.distribution') as mock_dist:
            mock_dist_obj = Mock()
            mock_dist_obj.read_text.side_effect = FileNotFoundError()
            mock_dist.return_value = mock_dist_obj
            
            is_installed, method = tool_installer._is_package_installed('requests')
            assert is_installed is True
            assert method == 'system'
    
    def test_is_package_installed_not_found(self, tool_installer):
        """Test detection when package is not installed."""
        with patch('importlib.metadata.distribution') as mock_dist:
            from importlib.metadata import PackageNotFoundError
            mock_dist.side_effect = PackageNotFoundError()
            
            is_installed, method = tool_installer._is_package_installed('nonexistent')
            assert is_installed is False
            assert method == 'not_installed'
    
    def test_is_package_installed_fallback_pip_show(self, tool_installer):
        """Test fallback to pip show when importlib fails."""
        with patch('importlib.metadata.distribution', side_effect=Exception()):
            with patch('subprocess.run') as mock_run:
                mock_result = Mock()
                mock_result.returncode = 0
                mock_result.stdout = "Name: requests\nVersion: 2.28.0\n"
                mock_run.return_value = mock_result
                
                is_installed, method = tool_installer._is_package_installed('requests')
                assert is_installed is True
                assert method == 'pip'
    
    def test_is_package_installed_fallback_dpkg(self, tool_installer):
        """Test fallback to dpkg for Debian packages."""
        with patch('importlib.metadata.distribution', side_effect=Exception()):
            with patch('subprocess.run') as mock_run:
                # pip show fails
                mock_run.side_effect = [
                    Mock(returncode=1, stdout=""),  # pip show fails
                    Mock(returncode=0, stdout="ii  python3-requests  2.28.0-1  all")  # dpkg succeeds
                ]
                
                is_installed, method = tool_installer._is_package_installed('requests')
                assert is_installed is True
                assert method == 'system'


class TestPythonVersionDetection:
    """Tests for Python version detection."""
    
    def test_get_python_version(self, tool_installer):
        """Test Python version detection."""
        version = tool_installer._get_python_version()
        assert isinstance(version, tuple)
        assert len(version) == 3
        assert all(isinstance(v, int) for v in version)
        assert version[0] >= 3  # Python 3+


class TestBreakSystemPackagesFlag:
    """Tests for --break-system-packages flag detection."""
    
    def test_needs_break_system_packages_python_313(self, tool_installer):
        """Test that Python 3.13+ needs the flag."""
        with patch('sys.version_info', (3, 13, 0)):
            needs_flag = tool_installer._needs_break_system_packages()
            assert needs_flag is True
    
    def test_needs_break_system_packages_python_312(self, tool_installer):
        """Test that Python 3.12 does not need the flag."""
        with patch('sys.version_info', (3, 12, 0)):
            needs_flag = tool_installer._needs_break_system_packages()
            assert needs_flag is False
    
    def test_needs_break_system_packages_python_311(self, tool_installer):
        """Test that Python 3.11 does not need the flag."""
        with patch('sys.version_info', (3, 11, 0)):
            needs_flag = tool_installer._needs_break_system_packages()
            assert needs_flag is False


class TestPipInstallation:
    """Tests for pip installation logic."""
    
    @pytest.mark.asyncio
    async def test_install_pip_already_installed_system(self, tool_installer):
        """Test that system-installed packages are skipped."""
        tool = ToolMetadata(
            name="requests",
            description="HTTP library",
            category=ToolCategory.RECOMMENDED,
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="requests",
                sudo_required=False
            )
        )
        
        with patch.object(tool_installer, '_is_package_installed', return_value=(True, 'system')):
            result = await tool_installer._install_pip(tool, use_sudo=False)
            assert result is True
    
    @pytest.mark.asyncio
    async def test_install_pip_already_installed_pip(self, tool_installer):
        """Test that pip-installed packages are skipped."""
        tool = ToolMetadata(
            name="requests",
            description="HTTP library",
            category=ToolCategory.RECOMMENDED,
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="requests",
                sudo_required=False
            )
        )
        
        with patch.object(tool_installer, '_is_package_installed', return_value=(True, 'pip')):
            result = await tool_installer._install_pip(tool, use_sudo=False)
            assert result is True
    
    @pytest.mark.asyncio
    async def test_install_pip_success_user_space(self, tool_installer):
        """Test successful user-space installation."""
        tool = ToolMetadata(
            name="test-package",
            description="Test package",
            category=ToolCategory.OPTIONAL,
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="test-package",
                sudo_required=False
            )
        )
        
        with patch.object(tool_installer, '_is_package_installed', return_value=(False, 'not_installed')):
            with patch.object(tool_installer, '_run_command', new_callable=AsyncMock) as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                
                result = await tool_installer._install_pip(tool, use_sudo=False)
                assert result is True
    
    @pytest.mark.asyncio
    async def test_install_pip_already_satisfied(self, tool_installer):
        """Test that 'already satisfied' is treated as success."""
        tool = ToolMetadata(
            name="test-package",
            description="Test package",
            category=ToolCategory.OPTIONAL,
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="test-package",
                sudo_required=False
            )
        )
        
        with patch.object(tool_installer, '_is_package_installed', return_value=(False, 'not_installed')):
            with patch.object(tool_installer, '_run_command', new_callable=AsyncMock) as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="Requirement already satisfied: test-package",
                    stderr=""
                )
                
                result = await tool_installer._install_pip(tool, use_sudo=False)
                assert result is True
    
    @pytest.mark.asyncio
    async def test_install_pip_debian_conflict(self, tool_installer):
        """Test that Debian package conflicts are handled gracefully."""
        tool = ToolMetadata(
            name="cryptography",
            description="Cryptography library",
            category=ToolCategory.RECOMMENDED,
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="cryptography",
                sudo_required=False
            )
        )
        
        with patch.object(tool_installer, '_is_package_installed', return_value=(False, 'not_installed')):
            with patch.object(tool_installer, '_run_command', new_callable=AsyncMock) as mock_run:
                mock_run.return_value = Mock(
                    returncode=1,
                    stdout="",
                    stderr="uninstall-no-record-file: /usr/lib/python3/dist-packages/cryptography"
                )
                
                result = await tool_installer._install_pip(tool, use_sudo=False)
                assert result is True  # Should return True since package is available
    
    @pytest.mark.asyncio
    async def test_install_pip_externally_managed(self, tool_installer):
        """Test handling of externally managed Python environment."""
        tool = ToolMetadata(
            name="test-package",
            description="Test package",
            category=ToolCategory.OPTIONAL,
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="test-package",
                sudo_required=False
            )
        )
        
        with patch.object(tool_installer, '_is_package_installed', return_value=(False, 'not_installed')):
            with patch.object(tool_installer, '_run_command', new_callable=AsyncMock) as mock_run:
                # First attempt fails with externally managed error
                # The fallback to user-space should also fail
                mock_run.return_value = Mock(
                    returncode=1,
                    stdout="",
                    stderr="externally-managed-environment"
                )
                
                # Should raise SubprocessError after all methods fail
                with pytest.raises(subprocess.SubprocessError, match="externally managed"):
                    await tool_installer._install_pip(tool, use_sudo=False)
    
    @pytest.mark.asyncio
    async def test_install_pip_permission_denied_fallback_user(self, tool_installer):
        """Test fallback to user-space install on permission denied."""
        tool = ToolMetadata(
            name="test-package",
            description="Test package",
            category=ToolCategory.OPTIONAL,
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="test-package",
                sudo_required=False
            )
        )
        
        call_count = [0]
        
        async def mock_run(cmd):
            call_count[0] += 1
            # First call (system-wide) fails with permission
            if call_count[0] == 1:
                return Mock(
                    returncode=1,
                    stdout="",
                    stderr="Permission denied"
                )
            # Second call (user-space) succeeds
            else:
                return Mock(returncode=0, stdout="", stderr="")
        
        with patch.object(tool_installer, '_is_package_installed', return_value=(False, 'not_installed')):
            with patch.object(tool_installer, '_run_command', side_effect=mock_run):
                result = await tool_installer._install_pip(tool, use_sudo=False)
                assert result is True
    
    @pytest.mark.asyncio
    async def test_install_pip_package_not_found(self, tool_installer):
        """Test handling of package not found on PyPI."""
        tool = ToolMetadata(
            name="nonexistent-package-xyz",
            description="Nonexistent package",
            category=ToolCategory.OPTIONAL,
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="nonexistent-package-xyz",
                sudo_required=False
            )
        )
        
        with patch.object(tool_installer, '_is_package_installed', return_value=(False, 'not_installed')):
            with patch.object(tool_installer, '_run_command', new_callable=AsyncMock) as mock_run:
                mock_run.return_value = Mock(
                    returncode=1,
                    stdout="",
                    stderr="Could not find a version that satisfies the requirement nonexistent-package-xyz"
                )
                
                with pytest.raises(ValueError, match="not found on PyPI"):
                    await tool_installer._install_pip(tool, use_sudo=False)
    
    @pytest.mark.asyncio
    async def test_install_pip_pip_not_found(self, tool_installer):
        """Test handling when pip is not available."""
        tool = ToolMetadata(
            name="test-package",
            description="Test package",
            category=ToolCategory.OPTIONAL,
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="test-package",
                sudo_required=False
            )
        )
        
        with patch.object(tool_installer, '_is_package_installed', return_value=(False, 'not_installed')):
            with patch.object(tool_installer, '_run_command', new_callable=AsyncMock) as mock_run:
                mock_run.return_value = Mock(
                    returncode=1,
                    stdout="",
                    stderr="pip: command not found"
                )
                
                with pytest.raises(FileNotFoundError, match="Pip is not installed"):
                    await tool_installer._install_pip(tool, use_sudo=False)


class TestRetryLogic:
    """Tests for retry logic with network errors."""
    
    @pytest.mark.asyncio
    async def test_network_error_retry(self, tool_installer):
        """Test that network errors trigger retries."""
        tool = ToolMetadata(
            name="test-package",
            description="Test package",
            category=ToolCategory.OPTIONAL,
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="test-package",
                sudo_required=False
            )
        )
        
        call_count = [0]
        
        async def mock_run(cmd):
            call_count[0] += 1
            # First two calls fail with network error
            if call_count[0] <= 2:
                return Mock(
                    returncode=1,
                    stdout="",
                    stderr="Network is unreachable"
                )
            # Third call succeeds
            else:
                return Mock(returncode=0, stdout="", stderr="")
        
        with patch.object(tool_installer, '_is_package_installed', return_value=(False, 'not_installed')):
            with patch.object(tool_installer, '_run_command', side_effect=mock_run):
                result = await tool_installer._install_pip(tool, use_sudo=False)
                assert result is True
                assert call_count[0] == 3  # Should have retried


class TestPlatformDetection:
    """Tests for platform detection."""
    
    def test_detect_platform_linux_debian(self, tool_installer):
        """Test detection of Debian."""
        with patch('platform.system', return_value='Linux'):
            with patch('builtins.open', mock_open(read_data='PRETTY_NAME="Debian GNU/Linux 12"\n')):
                platform = tool_installer._detect_platform()
                assert platform == 'debian'
    
    def test_detect_platform_linux_ubuntu(self, tool_installer):
        """Test detection of Ubuntu."""
        with patch('platform.system', return_value='Linux'):
            with patch('builtins.open', mock_open(read_data='PRETTY_NAME="Ubuntu 22.04 LTS"\n')):
                platform = tool_installer._detect_platform()
                assert platform == 'ubuntu'
    
    def test_detect_platform_linux_parrot(self, tool_installer):
        """Test detection of Parrot Security OS."""
        with patch('platform.system', return_value='Linux'):
            with patch('builtins.open', mock_open(read_data='PRETTY_NAME="Parrot Security OS"\n')):
                platform = tool_installer._detect_platform()
                assert platform == 'parrot'
    
    def test_detect_platform_windows(self, tool_installer):
        """Test detection of Windows."""
        with patch('platform.system', return_value='Windows'):
            platform = tool_installer._detect_platform()
            assert platform == 'windows'
    
    def test_detect_platform_macos(self, tool_installer):
        """Test detection of macOS."""
        with patch('platform.system', return_value='Darwin'):
            platform = tool_installer._detect_platform()
            assert platform == 'macos'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
