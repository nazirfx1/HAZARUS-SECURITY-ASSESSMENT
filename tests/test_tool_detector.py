"""
HAZARUS Tool Detector Tests
Test tool detection functionality.
"""

import pytest
import asyncio
from hazarus.tools.detector import ToolDetector, ALTERNATIVE_COMMANDS, GUI_TOOLS
from hazarus.tools.registry import ToolRegistry, ToolMetadata, ToolDetection, ToolCategory, InstallationType


def test_alternative_commands_mapping():
    """Test that alternative commands mapping is properly defined."""
    assert isinstance(ALTERNATIVE_COMMANDS, dict)
    assert len(ALTERNATIVE_COMMANDS) > 0
    
    # Check some common tools have alternatives
    assert "zap" in ALTERNATIVE_COMMANDS
    assert "burpsuite" in ALTERNATIVE_COMMANDS
    assert "metasploit" in ALTERNATIVE_COMMANDS
    
    # Verify alternatives are lists
    for tool, alts in ALTERNATIVE_COMMANDS.items():
        assert isinstance(alts, list)
        assert len(alts) > 0


def test_gui_tools_mapping():
    """Test that GUI tools mapping is properly defined."""
    assert isinstance(GUI_TOOLS, dict)
    assert len(GUI_TOOLS) > 0
    
    # Check some GUI tools are defined
    assert "burpsuite" in GUI_TOOLS
    assert "zap" in GUI_TOOLS
    assert "wireshark" in GUI_TOOLS


def test_detector_initialization():
    """Test tool detector initialization."""
    registry = ToolRegistry()
    detector = ToolDetector(registry=registry)
    
    assert detector.registry is not None
    assert detector.cache == {}
    assert detector.debug is False


def test_detector_with_debug():
    """Test tool detector with debug mode enabled."""
    detector = ToolDetector(debug=True)
    
    assert detector.debug is True


def test_build_command_list():
    """Test building command list with alternatives."""
    registry = ToolRegistry()
    detector = ToolDetector(registry=registry)
    
    # Create a mock tool detection
    detection = ToolDetection(
        command="nmap",
        version_flag="--version",
        version_pattern=r"Nmap version ([\d.]+)",
        fallback_commands=["nmap-full"]
    )
    
    commands = detector._build_command_list("nmap", detection)
    
    assert "nmap" in commands
    assert "nmap-full" in commands
    # Should include alternatives from mapping
    assert len(commands) >= 2


def test_build_command_list_no_duplicates():
    """Test that command list doesn't have duplicates."""
    registry = ToolRegistry()
    detector = ToolDetector(registry=registry)
    
    detection = ToolDetection(
        command="zap",
        version_flag="-version",
        version_pattern=r"ZAP ([\d.]+)",
        fallback_commands=["zap-cli"]  # This is also in ALTERNATIVE_COMMANDS
    )
    
    commands = detector._build_command_list("zap", detection)
    
    # Check no duplicates
    assert len(commands) == len(set(commands))


@pytest.mark.asyncio
async def test_check_tool_not_in_registry():
    """Test checking a tool that doesn't exist in registry."""
    detector = ToolDetector()
    
    status = await detector.check_tool("nonexistent_tool")
    
    assert status.installed is False
    assert status.compatible is False
    assert "not found in registry" in status.compatible_reason


@pytest.mark.asyncio
async def test_check_tool_no_detection_config():
    """Test checking a tool with no detection configuration."""
    registry = ToolRegistry()
    
    # Add a tool without detection config
    registry.tools['test_tool'] = ToolMetadata(
        name="Test Tool",
        description="A test tool",
        category=ToolCategory.OPTIONAL,
        required=False,
        detection=None
    )
    
    detector = ToolDetector(registry=registry)
    status = await detector.check_tool("test_tool")
    
    assert status.installed is False
    assert "No detection configuration" in status.compatible_reason


@pytest.mark.asyncio
async def test_cache_functionality():
    """Test that tool detection results are cached."""
    detector = ToolDetector()
    
    # Check a tool twice
    status1 = await detector.check_tool("nmap")
    status2 = await detector.check_tool("nmap")
    
    # Should return the same cached result
    assert status1 == status2


def test_clear_cache():
    """Test clearing the detection cache."""
    detector = ToolDetector()
    
    # Add something to cache
    detector.cache['test'] = 'value'
    assert len(detector.cache) > 0
    
    # Clear cache
    detector.clear_cache()
    assert len(detector.cache) == 0


@pytest.mark.asyncio
async def test_check_package_installed():
    """Test checking if a package is installed via APT."""
    detector = ToolDetector()
    
    # Test with a package that likely exists (e.g., coreutils)
    result = await detector._check_package_installed("coreutils")
    # Should return True or False, not raise an exception
    assert isinstance(result, bool)
    
    # Test with a package that likely doesn't exist
    result = await detector._check_package_installed("nonexistent-package-12345")
    assert isinstance(result, bool)


@pytest.mark.asyncio
async def test_search_in_system_paths():
    """Test searching for commands in system paths."""
    detector = ToolDetector()
    
    # Search for a common command that should exist
    path = await detector._search_in_system_paths("python3")
    # Should return a path or None
    assert path is None or isinstance(path, str)
    
    # Search for a command that likely doesn't exist
    path = await detector._search_in_system_paths("nonexistent-command-12345")
    assert path is None


@pytest.mark.asyncio
async def test_get_tool_version():
    """Test getting tool version."""
    detector = ToolDetector()
    
    # Try to get version of python3
    version = await detector._get_tool_version(
        "python3",
        "--version",
        r"Python ([\d.]+)"
    )
    
    # Should return a version string or None
    assert version is None or isinstance(version, str)


@pytest.mark.asyncio
async def test_check_all_tools():
    """Test checking all registered tools."""
    detector = ToolDetector()
    
    results = await detector.check_all_tools()
    
    assert isinstance(results, dict)
    assert len(results) > 0
    
    # All values should be ToolStatus objects
    for status in results.values():
        assert hasattr(status, 'installed')
        assert hasattr(status, 'version')
        assert hasattr(status, 'compatible')


@pytest.mark.asyncio
async def test_check_required_tools():
    """Test checking only required tools."""
    detector = ToolDetector()
    
    results = await detector.check_required_tools()
    
    assert isinstance(results, dict)
    # Should have fewer tools than check_all_tools
    all_results = await detector.check_all_tools()
    assert len(results) <= len(all_results)


@pytest.mark.asyncio
async def test_check_missing_tools():
    """Test getting list of missing tools."""
    detector = ToolDetector()
    
    missing = await detector.check_missing_tools()
    
    assert isinstance(missing, dict)
    # All should be not installed
    for status in missing.values():
        assert status.installed is False


@pytest.mark.asyncio
async def test_check_incompatible_tools():
    """Test getting list of incompatible tools."""
    detector = ToolDetector()
    
    incompatible = await detector.check_incompatible_tools()
    
    assert isinstance(incompatible, dict)
    # All should be installed but not compatible
    for status in incompatible.values():
        assert status.installed is True
        assert status.compatible is False


def test_parse_version():
    """Test version parsing from command output."""
    detector = ToolDetector()
    
    # Test successful parsing
    output = "Nmap version 7.94 ( https://nmap.org )"
    version = detector._parse_version(output, r"Nmap version ([\d.]+)")
    assert version == "7.94"
    
    # Test no match
    output = "Some other output"
    version = detector._parse_version(output, r"Version ([\d.]+)")
    assert version is None


def test_compare_versions():
    """Test version comparison."""
    detector = ToolDetector()
    
    # Test equal versions
    assert detector._compare_versions("1.0.0", "1.0.0") == 0
    
    # Test greater than
    assert detector._compare_versions("2.0.0", "1.0.0") == 1
    assert detector._compare_versions("1.1.0", "1.0.0") == 1
    assert detector._compare_versions("1.0.1", "1.0.0") == 1
    
    # Test less than
    assert detector._compare_versions("1.0.0", "2.0.0") == -1
    assert detector._compare_versions("1.0.0", "1.1.0") == -1
    assert detector._compare_versions("1.0.0", "1.0.1") == -1
    
    # Test different length versions
    assert detector._compare_versions("1.0", "1.0.0") == 0
    assert detector._compare_versions("1.0.1", "1.0") == 1


def test_check_compatibility():
    """Test compatibility checking."""
    registry = ToolRegistry()
    detector = ToolDetector(registry=registry)
    
    # Get nmap tool (has version constraint)
    tool = registry.get_tool("nmap")
    
    # Test compatible version
    compatible, reason = detector._check_compatibility(tool, "7.94")
    assert compatible is True
    
    # Test incompatible version
    compatible, reason = detector._check_compatibility(tool, "7.50")
    assert compatible is False
    assert "required" in reason.lower()
    
    # Test no version
    compatible, reason = detector._check_compatibility(tool, None)
    assert compatible is True  # Can't determine without version


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
