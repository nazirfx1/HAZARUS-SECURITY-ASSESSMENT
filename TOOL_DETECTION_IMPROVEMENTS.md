# Tool Detection Improvements for Parrot OS

## Summary

Enhanced the tool detection system in `hazarus/tools/detector.py` to properly detect pre-installed tools in Parrot OS. The detector now supports alternative command names, system path searching, and GUI tool detection via package manager.

## Changes Made

### 1. Enhanced ToolDetector Class (`hazarus/tools/detector.py`)

#### New Features:
- **Alternative Command Names**: Added comprehensive mapping of alternative command names for tools commonly installed in Parrot OS
- **System Path Searching**: Implemented searching in common system paths when tools are not in PATH
- **GUI Tool Detection**: Added support for detecting GUI tools (like Burp Suite, ZAP) via package manager (dpkg)
- **Debug Logging**: Added optional debug logging to show detection process
- **Fallback Command Support**: Properly implemented the `fallback_commands` field that was previously unused

#### New Constants:
- `COMMON_SYSTEM_PATHS`: List of common system paths to search for tools
- `ALTERNATIVE_COMMANDS`: Dictionary mapping tool names to alternative command names
- `GUI_TOOLS`: Dictionary of GUI tools that may not have CLI commands

#### New Methods:
- `_build_command_list()`: Builds comprehensive list of commands to try for tool detection
- `_search_in_system_paths()`: Searches for commands in common system paths
- `_get_tool_version()`: Gets tool version with better error handling
- `_check_package_installed()`: Checks if a package is installed via APT/dpkg

#### Enhanced Methods:
- `check_tool()`: Now uses alternative commands, system path search, and GUI tool detection
- `__init__()`: Added optional `debug` parameter for debug logging

### 2. Updated Tool Registry (`hazarus/tools/registry.py`)

Updated tool definitions to include alternative command names in the `fallback_commands` field:

- **ZAP**: Added "zap.sh" to fallback commands
- **Burp Suite**: Added "burp" to fallback commands
- **Metasploit**: Added "msfvenom" and "msf" to fallback commands
- **Gobuster**: Added APT as fallback installation method
- **SQLMap**: Fixed version pattern regex
- **Hydra**: Added "hydra-gtk" to fallback commands
- **John the Ripper**: Added "john-the-ripper" to fallback commands
- **Aircrack-ng**: Added "airmon-ng" and "airodump-ng" to fallback commands
- **Ghidra**: Added "ghidraRun" to fallback commands
- **BloodHound**: Added "bloodhound" to fallback commands
- **Masscan**: Added fallback_commands field
- **Nuclei**: Added APT as fallback installation method

### 3. Test Suite (`tests/test_tool_detector.py`)

Created comprehensive test suite for the enhanced detector:
- 20 unit tests covering all new functionality
- Tests for alternative command mapping
- Tests for GUI tool detection
- Tests for system path searching
- Tests for version parsing and comparison
- Tests for compatibility checking
- Tests for cache functionality

All tests pass successfully.

### 4. Manual Test Script (`test_tool_detection.py`)

Created a standalone test script for manual testing of tool detection:
- Tests specific tools commonly pre-installed in Parrot OS
- Shows detection process with debug output
- Provides summary of installed vs missing tools
- Tests alternative command mapping
- Tests GUI tool detection
- Tests system path search

## Alternative Command Names Mapping

The following tools now have alternative command names defined:

| Tool | Primary Command | Alternative Commands |
|------|----------------|---------------------|
| zap | zap-cli | zap, zaproxy, zap.sh |
| burpsuite | burpsuite | burp |
| wireshark | tshark | wireshark |
| metasploit | msfconsole | msfvenom, msf |
| hydra | hydra | hydra-gtk |
| john | john | john-the-ripper |
| aircrack-ng | aircrack-ng | airmon-ng, airodump-ng |
| ghidra | analyzeHeadless | ghidraRun |
| bloodhound-python | bloodhound-python | bloodhound |
| theharvester | theHarvester | theharvester |

## GUI Tool Detection

GUI tools that may not have CLI commands are detected via package manager:
- **Burp Suite**: Checks for "burpsuite" package
- **OWASP ZAP**: Checks for "zaproxy" package
- **Wireshark**: Checks for "wireshark" package
- **Ghidra**: Checks for "ghidra" package

## System Paths Searched

The detector searches the following system paths when tools are not in PATH:
- `/usr/bin`
- `/usr/local/bin`
- `/opt/bin`
- `/snap/bin`
- `/home/linuxbrew/.linuxbrew/bin`
- `~/.local/bin`
- `/usr/sbin`
- `/sbin`

## Debug Mode

To enable debug logging for troubleshooting:
```python
detector = ToolDetector(debug=True)
```

This will show:
- Which commands are being tried
- Where commands are found
- Version detection attempts
- Package manager checks
- Why detection fails

## Usage Example

```python
from hazarus.tools.detector import ToolDetector

# Initialize detector with debug mode
detector = ToolDetector(debug=True)

# Check a specific tool
status = await detector.check_tool("nmap")
if status.installed:
    print(f"Nmap {status.version} found at {status.path}")
else:
    print(f"Nmap not found: {status.compatible_reason}")

# Check all tools
all_status = await detector.check_all_tools()
for tool_name, status in all_status.items():
    if status.installed:
        print(f"✓ {tool_name}: {status.version}")
    else:
        print(f"✗ {tool_name}: Not installed")
```

## Benefits

1. **Better Parrot OS Support**: Detects tools that are pre-installed in Parrot OS under different command names
2. **More Robust Detection**: Multiple fallback mechanisms ensure tools are detected even if installed non-standardly
3. **GUI Tool Support**: Can detect GUI tools that don't have CLI commands
4. **Better Debugging**: Debug logging helps troubleshoot detection issues
5. **Comprehensive Testing**: Full test suite ensures reliability

## Testing

Run the test suite:
```bash
pytest tests/test_tool_detector.py -v
```

Run the manual test script:
```bash
python test_tool_detection.py
```

## Future Enhancements

Potential future improvements:
- Add support for other package managers (snap, flatpak, pacman)
- Add more alternative command names for other tools
- Add detection for tools installed via Docker
- Add detection for tools in custom install paths
- Add version detection for GUI tools via package manager version info
