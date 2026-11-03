# Fallback Installation Methods Implementation

## Summary
This implementation adds fallback installation methods to the HAZARUS tool installer, allowing the framework to try alternative installation methods when the primary method fails.

## Changes Made

### 1. hazarus/tools/registry.py

#### ToolInstallation Dataclass (Line 40-50)
- Added `fallback_methods: List[InstallationType]` field to support multiple installation methods with priority
- Allows tools to specify primary and fallback installation types
- Example: A tool can try PIP first, then fall back to GitHub if PIP fails

#### ToolStatus Dataclass (Line 85-97)
- Added `installation_method: Optional[InstallationType]` field to track which installation method succeeded
- Added `detection_command: Optional[str]` field to track which command was used for detection
- Added `error_code: Optional[str]` field for categorizing installation failures

#### Example Tool Configurations
- **semgrep**: Configured with PIP as primary, GitHub as fallback
- **zap**: Configured with fallback detection commands (zap-cli, zap, zaproxy)

### 2. hazarus/tools/installer.py

#### Platform Detection (Line 129-159)
- Added `_detect_platform()` method to detect the current OS platform
- Supports: Ubuntu, Debian, Parrot, Kali, Fedora, Arch, macOS, Windows
- Stores detected platform in `self.current_platform`

#### Platform Compatibility Check (Line 161-176)
- Added `_is_platform_compatible()` method to check if a tool is compatible with current platform
- Returns tuple of (compatible, reason)
- Prevents installation attempts on incompatible platforms

#### Updated install_tool() Method (Line 178-280)
- Now checks platform compatibility before attempting installation
- Builds list of installation methods: primary + fallback methods
- Tries each installation method in order with detailed error reporting
- Tracks which method succeeded and reports it in ToolStatus
- Implements specific error handling for:
  - Permission errors
  - File not found (missing dependencies)
  - Timeout errors
  - Network errors
  - Disk space errors
  - Filesystem errors
- Returns ToolStatus with installation_method set to the successful method

#### Error Code Enum (Line 75-106)
- Added InstallationErrorCode enum for categorizing installation failures
- Categories: Network, Permission, Dependency, Configuration, System, Tool-specific, Unknown

### 3. hazarus/tools/detector.py

#### Updated check_tool() Method (Line 26-107)
- Now builds list of commands to try: primary + fallback commands
- Tries each command in order until one succeeds
- Tracks which command was used for detection
- Returns ToolStatus with detection_command set to the successful command
- If all commands fail, returns appropriate error message

## Usage Examples

### Tool Configuration with Fallback Installation Methods

```python
from hazarus.tools.registry import (
    ToolMetadata, ToolInstallation, ToolDetection,
    ToolCategory, InstallationType
)

# Tool with PIP primary, GitHub fallback
tool = ToolMetadata(
    name="semgrep",
    description="Static analysis tool",
    category=ToolCategory.OPTIONAL,
    detection=ToolDetection(
        command="semgrep",
        version_flag="--version",
        version_pattern=r"semgrep ([\d.]+)"
    ),
    installation=ToolInstallation(
        type=InstallationType.PIP,
        package="semgrep",
        version="1.0+",
        sudo_required=False,
        fallback_methods=[InstallationType.GITHUB],
        repo="semgrep/semgrep",
        asset_pattern=r"semgrep-.*-linux_amd64\.tgz",
        install_path="/usr/local/bin"
    )
)
```

### Tool Configuration with Fallback Detection Commands

```python
# Tool with multiple detection command options
tool = ToolMetadata(
    name="OWASP ZAP",
    description="Web application security scanner",
    category=ToolCategory.OPTIONAL,
    detection=ToolDetection(
        command="zap-cli",
        version_flag="-version",
        version_pattern=r"ZAP ([\d.]+)",
        fallback_commands=["zap", "zaproxy"]
    ),
    installation=ToolInstallation(
        type=InstallationType.APT,
        package="zaproxy",
        sudo_required=True
    )
)
```

### Installation Flow

1. **Platform Check**: Verifies tool is compatible with current platform
2. **Detection Check**: Checks if tool is already installed (with fallback commands)
3. **Installation Attempt**: Tries primary installation method
4. **Fallback Loop**: If primary fails, tries each fallback method in order
5. **Verification**: Verifies installation succeeded
6. **Status Report**: Returns ToolStatus with:
   - `installation_method`: Which method succeeded
   - `detection_command`: Which command detected the tool
   - `error_code`: Categorized error if installation failed

## Benefits

1. **Resilience**: Provides alternative installation methods when primary fails
2. **Flexibility**: Supports multiple package managers and installation sources
3. **Detection Robustness**: Handles tools with multiple possible command names
4. **Platform Safety**: Prevents installation attempts on incompatible platforms
5. **Better Reporting**: Tracks and reports which method succeeded
6. **Error Categorization**: Provides detailed error codes for troubleshooting

## Testing

All changes have been validated with:
- Python syntax validation (py_compile)
- Import testing
- Dataclass field testing
- Platform detection testing
- Fallback method configuration testing
