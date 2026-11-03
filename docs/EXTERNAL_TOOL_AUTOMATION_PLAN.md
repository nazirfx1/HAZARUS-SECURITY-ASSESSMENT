# External Tool Installation Automation Plan

## Overview

HAZARUS integrates with multiple external security tools. Currently, users must manually install these tools. This plan outlines an automated installation system to detect, install, and configure external tools on Parrot Security OS.

## Objectives

1. **Automated Detection** - Check which tools are installed
2. **Automated Installation** - Install missing tools via package managers
3. **Version Management** - Ensure compatible versions
4. **Configuration** - Configure tools for HAZARUS integration
5. **Validation** - Verify tools work correctly
6. **User Feedback** - Clear status reporting
7. **Graceful Degradation** - Framework works even if tools are missing

## External Tools Inventory

### Core Tools (Required for Basic Functionality)
| Tool | Purpose | Package Manager | Version Required |
|------|---------|----------------|-----------------|
| Nmap | Network scanning | apt (nmap) | 7.80+ |
| Anonsurf | Anonymity | apt (anonsurf) | Latest |
| Python | Runtime | apt (python3) | 3.11+ |

### Recommended Tools (Enhanced Functionality)
| Tool | Purpose | Package Manager | Version Required |
|------|---------|----------------|-----------------|
| Nikto | Web scanning | apt (nikto) | 2.1.6+ |
| Nuclei | Vulnerability scanning | GitHub release | 3.0+ |
| Amass | Subdomain enumeration | GitHub release | 5.0+ |
| Subfinder | Subdomain enumeration | GitHub release | 2.6+ |
| WHOIS | Domain info | apt (whois) | Latest |
| curl | HTTP requests | apt (curl) | Latest |
| wget | HTTP requests | apt (wget) | Latest |

### Optional Tools (Advanced Features)
| Tool | Purpose | Package Manager | Version Required |
|------|---------|----------------|-----------------|
| Semgrep | Static analysis | pip (semgrep) | 1.0+ |
| Gitleaks | Secret detection | GitHub release | 8.0+ |
| Trivy | Vulnerability scanning | GitHub release | 0.50+ |
| Metasploit | Exploitation | apt (metasploit-framework) | Latest |
| OWASP ZAP | Web scanning | apt (zaproxy) | Latest |
| p0f | OS fingerprinting | apt (p0f) | Latest |
| arping | ARP scanning | apt (arping) | Latest |
| fping | Fast ping | apt (fping) | Latest |
| atk6-inverse_lookup6 | IPv6 lookup | apt (thc-ipv6) | Latest |

## Architecture

### Component Structure

```
hazarus/
├── tools/
│   ├── __init__.py
│   ├── installer.py          # Main installer orchestration
│   ├── detector.py           # Tool detection logic
│   ├── downloader.py         # GitHub release downloader
│   ├── configurer.py         # Tool configuration
│   ├── validator.py          # Tool validation
│   └── registry.py           # Tool metadata registry
├── config/
│   └── tools.yaml           # Tool configuration database
```

### Tool Registry Format

```yaml
tools:
  nmap:
    name: "Nmap"
    description: "Network scanning tool"
    required: true
    detection:
      command: "nmap"
      version_flag: "--version"
      version_pattern: "Nmap version ([\\d.]+)"
    installation:
      type: "apt"
      package: "nmap"
      version: "7.80+"
    configuration:
      default_args: "-sS -sV -O"
    validation:
      test_command: "nmap localhost"
      expected_output: "localhost"

  nuclei:
    name: "Nuclei"
    description: "Vulnerability scanner"
    required: false
    detection:
      command: "nuclei"
      version_flag: "-version"
      version_pattern: "nuclei ([\\d.]+)"
    installation:
      type: "github"
      repo: "projectdiscovery/nuclei"
      asset_pattern: "nuclei_.*_linux_amd64.zip"
      version: "3.0+"
    configuration:
      templates_path: "~/.config/nuclei/templates"
    validation:
      test_command: "nuclei -version"
      expected_output: "nuclei"
```

## Implementation Plan

### Phase 1: Core Infrastructure (Week 1)

#### 1.1 Tool Registry
- Create `tools/registry.py` with ToolMetadata dataclass
- Load tool definitions from `config/tools.yaml`
- Support version constraints and dependencies
- Provide search and query methods

#### 1.2 Tool Detector
- Create `tools/detector.py`
- Implement `check_tool(tool_name)` method
- Parse version output with regex
- Return ToolStatus (installed, version, path, compatible)
- Cache results for performance

#### 1.3 CLI Integration
- Add `hazarus tools` command to interactive mode
- Subcommands:
  - `hazarus tools list` - Show all tools and status
  - `hazarus tools check` - Check installation status
  - `hazarus tools install <tool>` - Install specific tool
  - `hazarus tools install-all` - Install all missing tools
  - `hazarus tools update` - Update installed tools

### Phase 2: Package Manager Integration (Week 2)

#### 2.1 APT Installer
- Create `tools/installers/apt_installer.py`
- Implement `install(package)` method
- Handle sudo requirements
- Support version pinning
- Provide progress feedback

#### 2.2 Pip Installer
- Create `tools/installers/pip_installer.py`
- Install Python packages (Semgrep, etc.)
- Handle virtual environment detection
- Support user vs system installs

#### 2.3 GitHub Release Downloader
- Create `tools/downloader.py`
- Fetch latest release from GitHub API
- Download and extract assets
- Verify checksums
- Install to /usr/local/bin or ~/.local/bin

### Phase 3: Configuration & Validation (Week 3)

#### 3.1 Tool Configurer
- Create `tools/configurer.py`
- Configure Nmap scripts
- Set up Nuclei templates
- Configure Metasploit RPC
- Create default config files

#### 3.2 Tool Validator
- Create `tools/validator.py`
- Run test commands
- Verify expected output
- Check tool functionality
- Report validation results

#### 3.3 Dependency Resolution
- Handle tool dependencies
- Install in correct order
- Handle conflicts
- Provide rollback capability

### Phase 4: Interactive Integration (Week 4)

#### 4.1 Tools Menu Section
- Add `[15] External Tools` to main menu
- Show tool status table
- Install individual tools
- Install all missing tools
- Update tools
- Configure tools

#### 4.2 Startup Check
- On startup, check critical tools
- Warn if required tools missing
- Offer to install missing tools
- Skip optional tools gracefully

#### 4.3 Assessment Integration
- Check tool availability before use
- Skip tools if not installed
- Show warnings for missing recommended tools
- Fall back to alternative methods

## User Experience

### Interactive Mode Menu

```
╭─────────────────────────────────────────────────────────────────────────────────╮
│ External Tools                                                                    │
╰─────────────────────────────────────────────────────────────────────────────────╯
[1] List Tools
[2] Check Installation Status
[3] Install Missing Tools
[4] Install Specific Tool
[5] Update Installed Tools
[6] Configure Tools
[7] Validate Tools
[0] Back to Main Menu
```

### Status Table Display

```
Tool Status Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

┏━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ Tool                     ┃ Status     ┃ Version   ┃ Required         ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ Nmap                     │ ✓ Installed │ 7.94      │ Yes              │
│ Anonsurf                 │ ✓ Installed │ Latest    │ Yes              │
│ Nikto                    │ ✓ Installed │ 2.1.6     │ No               │
│ Nuclei                   │ ✗ Missing   │ N/A       │ No               │
│ Amass                    │ ✗ Missing   │ N/A       │ No               │
│ Subfinder                │ ✗ Missing   │ N/A       │ No               │
│ Semgrep                  │ ✗ Missing   │ N/A       │ No               │
│ Gitleaks                 │ ✗ Missing   │ N/A       │ No               │
└──────────────────────────┴─────────────┴───────────┴──────────────────┘

Press [3] to install missing tools...
```

### Installation Progress

```
Installing External Tools
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[1/6] Nuclei...
  Downloading from GitHub... ✓
  Extracting archive... ✓
  Installing to /usr/local/bin... ✓
  Verifying installation... ✓

[2/6] Amass...
  Downloading from GitHub... ✓
  Extracting archive... ✓
  Installing to /usr/local/bin... ✓
  Verifying installation... ✓

[3/6] Subfinder...
  Downloading from GitHub... ✓
  Extracting archive... ✓
  Installing to /usr/local/bin... ✓
  Verifying installation... ✓

[4/6] Semgrep...
  Installing via pip... ✓
  Verifying installation... ✓

[5/6] Gitleaks...
  Downloading from GitHub... ✓
  Extracting archive... ✓
  Installing to /usr/local/bin... ✓
  Verifying installation... ✓

[6/6] Trivy...
  Downloading from GitHub... ✓
  Extracting archive... ✓
  Installing to /usr/local/bin... ✓
  Verifying installation... ✓

Installation Complete: 6/6 tools installed successfully
```

## Error Handling

### Sudo Requirements
- Detect if sudo is available
- Prompt for sudo password
- Fall back to user-space installation if sudo unavailable
- Install to ~/.local/bin instead of /usr/local/bin

### Network Issues
- Retry failed downloads
- Use mirrors for package managers
- Support offline installation (provide packages locally)
- Timeout handling

### Conflicts
- Detect version conflicts
- Provide conflict resolution options
- Support force install
- Rollback on failure

### Platform Compatibility
- Detect OS distribution
- Use appropriate package manager (apt, dnf, pacman, etc.)
- Handle architecture differences (x86_64, arm64)
- Provide fallbacks for unsupported platforms

## Security Considerations

### Download Verification
- Verify GPG signatures when available
- Check SHA256 checksums
- Use HTTPS for all downloads
- Validate binary integrity

### Sudo Safety
- Explicit sudo prompts
- Log all sudo operations
- Require confirmation for system-wide installs
- Support user-space installation as default

### Repository Trust
- Only use trusted sources (official repos, GitHub releases)
- Verify GitHub release authenticity
- Check for signed releases
- Warn about unverified sources

## Testing Strategy

### Unit Tests
- Test tool detection logic
- Test version parsing
- Test installer mock execution
- Test validator logic

### Integration Tests
- Test actual tool installation (in container)
- Test configuration generation
- Test validation
- Test rollback

### Manual Testing
- Test on fresh Parrot OS install
- Test on Debian
- Test on Ubuntu
- Test with minimal sudo permissions

## Milestones

### Milestone 1: Core Infrastructure (Week 1)
- [ ] Tool registry implementation
- [ ] Tool detector implementation
- [ ] CLI commands added
- [ ] Basic tool listing working

### Milestone 2: Installation (Week 2)
- [ ] APT installer working
- [ ] Pip installer working
- [ ] GitHub downloader working
- [ ] Can install basic tools

### Milestone 3: Configuration (Week 3)
- [ ] Tool configurator working
- [ ] Tool validator working
- [ ] Dependency resolution working
- [ ] Tools work with HAZARUS

### Milestone 4: Integration (Week 4)
- [ ] Interactive menu added
- [ ] Startup check working
- [ ] Assessment integration working
- [ ] Full user flow working

## Success Criteria

- [ ] All core tools auto-detected correctly
- [ ] Missing tools can be installed with one command
- [ ] Installation progress is clearly shown
- [ ] Tools work correctly after installation
- [ ] Framework works even if optional tools missing
- [ ] User experience is intuitive
- [ ] Security best practices followed
- [ ] Error handling is robust

## Risks & Mitigations

### Risk: Sudo Requirement
- **Mitigation:** Support user-space installation to ~/.local/bin
- **Fallback:** Warn if tool requires sudo and offer alternative

### Risk: Network Connectivity
- **Mitigation:** Retry with exponential backoff
- **Fallback:** Support offline installation packages

### Risk: Version Conflicts
- **Mitigation:** Version pinning in registry
- **Fallback:** Allow force install with warning

### Risk: Platform Incompatibility
- **Mitigation:** Comprehensive platform detection
- **Fallback:** Skip tool with clear message

## Future Enhancements

- Tool update notifications
- Automatic background updates
- Tool health monitoring
- Tool performance benchmarking
- Custom tool definitions
- Tool plugin system
- Tool marketplace integration
