# Tool Installation Workflow Improvements

## Summary of Changes to hazarus/interactive.py

### 1. Enhanced `install_missing_tools()` Method

**Improvements:**
- **Per-tool progress display**: Shows progress for each tool during bulk installation (e.g., "[1/5] Installing nmap...")
- **Real-time feedback**: Displays installation method used for successful installations (e.g., "nmap installed via apt")
- **Actionable error messages**: Converts generic errors to actionable suggestions using `_get_actionable_error_message()`
- **Automatic retry offer**: After installation, prompts user to retry failed tools
- **Failed installation tracking**: Stores failed installations in `self.failed_installations` for later retry

**New Features:**
- Shows count of missing tools before installation
- Displays which installation method succeeded for each tool
- Provides specific error explanations for failed installations
- Offers immediate retry option for failed tools

### 2. Enhanced `install_specific_tool()` Method

**Improvements:**
- **Tool validation**: Checks if tool exists in registry before attempting installation
- **Multiple installation methods display**: Shows all available installation methods (primary + fallbacks)
- **Fallback method support**: If primary method fails, offers to try alternative methods
- **Success method reporting**: Shows which installation method succeeded
- **Interactive fallback selection**: Allows user to choose specific fallback method to try

**New Features:**
- Lists available installation methods before starting
- Supports interactive selection of fallback methods
- Shows which method was used for successful installation
- Tracks failed installations for retry functionality

### 3. New Menu Option: "Retry Failed Installations"

**New Method: `retry_failed_installations()`**
- Shows list of tools that failed in last installation attempt
- Displays actionable error messages for each failed tool
- Provides options:
  - Retry all failed tools at once
  - Retry specific tool by number
  - Cancel operation
- Supports alternative method selection for retry

**Supporting Methods:**
- `_retry_all_failed()`: Retries all failed installations in bulk
  - Shows progress for each retry
  - Removes successfully installed tools from failed list
  - Provides suggestions for tools that still fail
  
- `_retry_single_tool()`: Retries a specific tool with method selection
  - Shows available alternative methods
  - Allows user to select specific method to try
  - Displays success/failure with method used

### 4. Improved Error Messages

**New Method: `_get_actionable_error_message()`**

Converts generic error messages to actionable suggestions:

| Error Pattern | Actionable Message |
|--------------|-------------------|
| Permission denied / sudo | "Permission denied - Run with sudo or install to user directory" |
| Network / connection / timeout | "Network error - Check internet connection and retry" |
| Rate limit / 429 | "Rate limited - Wait and retry, or use alternative method" |
| Package not found / 404 | "Package not found - Try alternative installation method" |
| Dependency missing | "Missing dependency - Install required dependencies first" |
| Disk space | "Disk space full - Free up space and retry" |
| APT-specific | "APT installation failed - Try: sudo apt update && sudo apt install <package>" |
| Pip-specific | "Pip installation failed - Try: pip install --user <package> or use --break-system-packages" |
| GitHub/download | "GitHub download failed - Check repo URL or download manually" |

### 5. Menu Structure Updates

**External Tools Menu (Option 17):**
- Updated from 6 options to 7 options
- Added new option [5]: "Retry Failed Installations"
- Renumbered subsequent options (Configure → 6, Validate → 7)
- Updated prompt to accept 0-7 range

### 6. Instance Variable Addition

**New Attribute: `self.failed_installations`**
- Dictionary to track failed installations across the session
- Maps tool names to their ToolStatus objects
- Persisted for retry functionality
- Cleared when tools are successfully installed

## Code Changes Summary

### Lines Modified
- **Line 18**: Added import for `ToolStatus` from `hazarus.tools.registry`
- **Lines 24-39**: Added `self.failed_installations = {}` to `__init__`
- **Lines 1708-1740**: Updated External Tools menu to include option 5 for retry
- **Lines 1787-1851**: Completely rewrote `install_missing_tools()` with enhanced features
- **Lines 1853-1924**: Completely rewrote `install_specific_tool()` with fallback support
- **Lines 1926-2118**: Added three new methods:
  - `retry_failed_installations()` - Main retry menu
  - `_retry_all_failed()` - Bulk retry implementation
  - `_retry_single_tool()` - Single tool retry with method selection
  - `_get_actionable_error_message()` - Error message translation

### Total Lines Added
- Approximately 200+ lines of new functionality
- Enhanced user experience with detailed progress and error handling
- Improved error messages with actionable suggestions

## User Experience Improvements

### Before
- Bulk installation showed no per-tool progress
- Generic error messages without solutions
- No retry mechanism for failed installations
- No fallback method support
- User had to manually retry failed tools

### After
- Real-time progress for each tool during installation
- Actionable error messages with specific solutions
- Automatic retry option after failed installations
- Support for multiple installation methods with fallback
- Dedicated retry menu for failed installations
- Alternative method selection for problematic tools
- Clear indication of which installation method succeeded

## Testing Recommendations

1. Test bulk installation with some tools that will fail
2. Verify per-tool progress display
3. Test retry functionality with failed tools
4. Test alternative method selection
5. Verify error message translation
6. Test with sudo and without sudo
7. Verify failed_installations tracking across menu navigation
