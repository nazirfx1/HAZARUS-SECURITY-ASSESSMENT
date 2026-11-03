"""
HAZARUS Tool Registry
Manages metadata and configuration for external tools.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from pathlib import Path
import yaml
from enum import Enum


class ToolCategory(Enum):
    """Tool category classification."""
    CORE = "core"
    RECOMMENDED = "recommended"
    OPTIONAL = "optional"


class InstallationType(Enum):
    """Installation method types."""
    APT = "apt"
    PIP = "pip"
    GITHUB = "github"
    SNAP = "snap"
    MANUAL = "manual"


@dataclass
class ToolDetection:
    """Tool detection configuration."""
    command: str
    version_flag: str
    version_pattern: str
    fallback_commands: List[str] = field(default_factory=list)


@dataclass
class ToolInstallation:
    """Tool installation configuration."""
    type: InstallationType
    package: Optional[str] = None
    repo: Optional[str] = None
    asset_pattern: Optional[str] = None
    version: Optional[str] = None
    sudo_required: bool = True
    install_path: Optional[str] = None


@dataclass
class ToolConfiguration:
    """Tool configuration options."""
    default_args: Optional[str] = None
    config_file: Optional[str] = None
    environment_vars: Dict[str, str] = field(default_factory=dict)
    templates_path: Optional[str] = None


@dataclass
class ToolValidation:
    """Tool validation configuration."""
    test_command: str
    expected_output: Optional[str] = None
    exit_code: int = 0


@dataclass
class ToolMetadata:
    """Complete metadata for a tool."""
    name: str
    description: str
    category: ToolCategory
    required: bool = False
    detection: Optional[ToolDetection] = None
    installation: Optional[ToolInstallation] = None
    configuration: Optional[ToolConfiguration] = None
    validation: Optional[ToolValidation] = None
    dependencies: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=lambda: ["linux", "debian", "ubuntu", "parrot"])


@dataclass
class ToolStatus:
    """Current status of a tool."""
    name: str
    installed: bool = False
    version: Optional[str] = None
    path: Optional[str] = None
    compatible: bool = True
    compatible_reason: Optional[str] = None
    last_checked: Optional[str] = None


class ToolRegistry:
    """Registry for managing tool metadata and configuration."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize tool registry.
        
        Args:
            config_path: Path to tools.yaml configuration file
        """
        self.config_path = config_path or self._get_default_config_path()
        self.tools: Dict[str, ToolMetadata] = {}
        self._load_tools()
    
    def _get_default_config_path(self) -> str:
        """Get default configuration file path."""
        # Try project config first
        project_root = Path(__file__).parent.parent.parent
        config_file = project_root / "config" / "tools.yaml"
        
        if config_file.exists():
            return str(config_file)
        
        # Fallback to embedded config
        return ""
    
    def _load_tools(self):
        """Load tool definitions from configuration file."""
        if not self.config_path or not os.path.exists(self.config_path):
            self._load_embedded_tools()
            return
        
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if not config or 'tools' not in config:
                self._load_embedded_tools()
                return
            
            for tool_name, tool_config in config['tools'].items():
                self.tools[tool_name] = self._parse_tool_config(tool_name, tool_config)
        
        except Exception as e:
            print(f"Warning: Failed to load tools config: {e}")
            self._load_embedded_tools()
    
    def _load_embedded_tools(self):
        """Load embedded tool definitions as fallback."""
        # Core tools
        self.tools['nmap'] = ToolMetadata(
            name="Nmap",
            description="Network scanning tool",
            category=ToolCategory.CORE,
            required=True,
            detection=ToolDetection(
                command="nmap",
                version_flag="--version",
                version_pattern=r"Nmap version ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="nmap",
                version="7.80+",
                sudo_required=True
            ),
            configuration=ToolConfiguration(
                default_args="-sS -sV -O"
            ),
            validation=ToolValidation(
                test_command="nmap localhost",
                exit_code=0
            )
        )
        
        self.tools['anonsurf'] = ToolMetadata(
            name="Anonsurf",
            description="Tor-based anonymity tool",
            category=ToolCategory.CORE,
            required=True,
            detection=ToolDetection(
                command="anonsurf",
                version_flag="status",
                version_pattern=r"Anonsurf"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="anonsurf",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="which anonsurf",
                exit_code=0
            )
        )
        
        # Recommended tools
        self.tools['nikto'] = ToolMetadata(
            name="Nikto",
            description="Web server scanner",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="nikto",
                version_flag="-Version",
                version_pattern=r"Nikto/([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="nikto",
                version="2.1.6+",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="nikto -Version",
                exit_code=0
            )
        )
        
        self.tools['nuclei'] = ToolMetadata(
            name="Nuclei",
            description="Vulnerability scanner",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="nuclei",
                version_flag="-version",
                version_pattern=r"nuclei ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.GITHUB,
                repo="projectdiscovery/nuclei",
                asset_pattern=r"nuclei_.*_linux_amd64\.zip",
                version="3.0+",
                sudo_required=True,
                install_path="/usr/local/bin"
            ),
            configuration=ToolConfiguration(
                templates_path="~/.config/nuclei/templates"
            ),
            validation=ToolValidation(
                test_command="nuclei -version",
                expected_output="nuclei"
            )
        )
        
        self.tools['amass'] = ToolMetadata(
            name="Amass",
            description="Subdomain enumeration",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="amass",
                version_flag="version",
                version_pattern=r"amass version ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.GITHUB,
                repo="owasp-amass/amass",
                asset_pattern=r"amass_.*_linux_amd64\.zip",
                version="5.0+",
                sudo_required=True,
                install_path="/usr/local/bin"
            ),
            validation=ToolValidation(
                test_command="amass version",
                exit_code=0
            )
        )
        
        self.tools['subfinder'] = ToolMetadata(
            name="Subfinder",
            description="Subdomain discovery",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="subfinder",
                version_flag="-version",
                version_pattern=r"subfinder ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.GITHUB,
                repo="projectdiscovery/subfinder",
                asset_pattern=r"subfinder_.*_linux_amd64\.zip",
                version="2.6+",
                sudo_required=True,
                install_path="/usr/local/bin"
            ),
            validation=ToolValidation(
                test_command="subfinder -version",
                exit_code=0
            )
        )
        
        self.tools['whois'] = ToolMetadata(
            name="WHOIS",
            description="Domain information lookup",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="whois",
                version_flag="--version",
                version_pattern=r"(\d+\.\d+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="whois",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="which whois",
                exit_code=0
            )
        )
        
        # Optional tools
        self.tools['semgrep'] = ToolMetadata(
            name="Semgrep",
            description="Static analysis tool",
            category=ToolCategory.OPTIONAL,
            required=False,
            detection=ToolDetection(
                command="semgrep",
                version_flag="--version",
                version_pattern=r"semgrep ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="semgrep",
                version="1.0+",
                sudo_required=False
            ),
            validation=ToolValidation(
                test_command="semgrep --version",
                exit_code=0
            )
        )
        
        self.tools['gitleaks'] = ToolMetadata(
            name="Gitleaks",
            description="Secret detection",
            category=ToolCategory.OPTIONAL,
            required=False,
            detection=ToolDetection(
                command="gitleaks",
                version_flag="version",
                version_pattern=r"version ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.GITHUB,
                repo="gitleaks/gitleaks",
                asset_pattern=r"gitleaks_.*_linux_amd64\.tar\.gz",
                version="8.0+",
                sudo_required=True,
                install_path="/usr/local/bin"
            ),
            validation=ToolValidation(
                test_command="gitleaks version",
                exit_code=0
            )
        )
        
        self.tools['trivy'] = ToolMetadata(
            name="Trivy",
            description="Vulnerability scanner",
            category=ToolCategory.OPTIONAL,
            required=False,
            detection=ToolDetection(
                command="trivy",
                version_flag="version",
                version_pattern=r"Version: ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.GITHUB,
                repo="aquasecurity/trivy",
                asset_pattern=r"trivy_.*_Linux-64bit\.tar\.gz",
                version="0.50+",
                sudo_required=True,
                install_path="/usr/local/bin"
            ),
            validation=ToolValidation(
                test_command="trivy version",
                exit_code=0
            )
        )
    
    def _parse_tool_config(self, name: str, config: dict) -> ToolMetadata:
        """Parse tool configuration from YAML."""
        category = ToolCategory(config.get('category', 'optional'))
        
        detection = None
        if 'detection' in config:
            det = config['detection']
            detection = ToolDetection(
                command=det['command'],
                version_flag=det.get('version_flag', '--version'),
                version_pattern=det.get('version_pattern', r'([\d.]+)'),
                fallback_commands=det.get('fallback_commands', [])
            )
        
        installation = None
        if 'installation' in config:
            inst = config['installation']
            installation = ToolInstallation(
                type=InstallationType(inst['type']),
                package=inst.get('package'),
                repo=inst.get('repo'),
                asset_pattern=inst.get('asset_pattern'),
                version=inst.get('version'),
                sudo_required=inst.get('sudo_required', True),
                install_path=inst.get('install_path')
            )
        
        configuration = None
        if 'configuration' in config:
            conf = config['configuration']
            configuration = ToolConfiguration(
                default_args=conf.get('default_args'),
                config_file=conf.get('config_file'),
                environment_vars=conf.get('environment_vars', {}),
                templates_path=conf.get('templates_path')
            )
        
        validation = None
        if 'validation' in config:
            val = config['validation']
            validation = ToolValidation(
                test_command=val['test_command'],
                expected_output=val.get('expected_output'),
                exit_code=val.get('exit_code', 0)
            )
        
        return ToolMetadata(
            name=config['name'],
            description=config['description'],
            category=category,
            required=config.get('required', False),
            detection=detection,
            installation=installation,
            configuration=configuration,
            validation=validation,
            dependencies=config.get('dependencies', []),
            platforms=config.get('platforms', ['linux'])
        )
    
    def get_tool(self, name: str) -> Optional[ToolMetadata]:
        """Get tool metadata by name."""
        return self.tools.get(name)
    
    def get_all_tools(self) -> Dict[str, ToolMetadata]:
        """Get all registered tools."""
        return self.tools
    
    def get_tools_by_category(self, category: ToolCategory) -> Dict[str, ToolMetadata]:
        """Get tools by category."""
        return {
            name: tool for name, tool in self.tools.items()
            if tool.category == category
        }
    
    def get_required_tools(self) -> Dict[str, ToolMetadata]:
        """Get required tools."""
        return {
            name: tool for name, tool in self.tools.items()
            if tool.required
        }
    
    def get_optional_tools(self) -> Dict[str, ToolMetadata]:
        """Get optional tools."""
        return {
            name: tool for name, tool in self.tools.items()
            if not tool.required
        }
    
    def search_tools(self, query: str) -> List[ToolMetadata]:
        """Search tools by name or description."""
        query = query.lower()
        results = []
        for tool in self.tools.values():
            if query in tool.name.lower() or query in tool.description.lower():
                results.append(tool)
        return results
