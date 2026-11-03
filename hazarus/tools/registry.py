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
        
        # Additional tools used by the framework
        self.tools['zap'] = ToolMetadata(
            name="OWASP ZAP",
            description="Web application security scanner",
            category=ToolCategory.OPTIONAL,
            required=False,
            detection=ToolDetection(
                command="zap-cli",
                version_flag="-version",
                version_pattern=r"ZAP ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="zaproxy",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="zap-cli -version",
                exit_code=0
            )
        )
        
        self.tools['whatweb'] = ToolMetadata(
            name="WhatWeb",
            description="Web technology identification",
            category=ToolCategory.OPTIONAL,
            required=False,
            detection=ToolDetection(
                command="whatweb",
                version_flag="--version",
                version_pattern=r"WhatWeb ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="whatweb",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="whatweb --version",
                exit_code=0
            )
        )
        
        self.tools['wpscan'] = ToolMetadata(
            name="WPScan",
            description="WordPress security scanner",
            category=ToolCategory.OPTIONAL,
            required=False,
            detection=ToolDetection(
                command="wpscan",
                version_flag="--version",
                version_pattern=r"WPScan ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="wpscan",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="wpscan --version",
                exit_code=0
            )
        )
        
        self.tools['gobuster'] = ToolMetadata(
            name="Gobuster",
            description="Directory bruteforcer",
            category=ToolCategory.OPTIONAL,
            required=False,
            detection=ToolDetection(
                command="gobuster",
                version_flag="version",
                version_pattern=r"([0-9.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.GITHUB,
                repo="go-appimage/gobuster",
                asset_pattern=r"gobuster_.*_linux_amd64\.AppImage",
                version="3.0+",
                sudo_required=True,
                install_path="/usr/local/bin"
            ),
            validation=ToolValidation(
                test_command="gobuster version",
                exit_code=0
            )
        )
        
        self.tools['sqlmap'] = ToolMetadata(
            name="SQLMap",
            description="SQL injection tool",
            category=ToolCategory.OPTIONAL,
            required=False,
            detection=ToolDetection(
                command="sqlmap",
                version_flag="--version",
                version_pattern=r"([0-9.]+\."
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="sqlmap",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="sqlmap --version",
                exit_code=0
            )
        )
        
        self.tools['metasploit'] = ToolMetadata(
            name="Metasploit",
            description="Exploitation framework",
            category=ToolCategory.OPTIONAL,
            required=False,
            detection=ToolDetection(
                command="msfconsole",
                version_flag="--version",
                version_pattern=r"Framework: ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="metasploit-framework",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="msfconsole --version",
                exit_code=0
            )
        )
        
        self.tools['p0f'] = ToolMetadata(
            name="p0f",
            description="OS fingerprinting tool",
            category=ToolCategory.OPTIONAL,
            required=False,
            detection=ToolDetection(
                command="p0f",
                version_flag="-v",
                version_pattern=r"p0f ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="p0f",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="p0f -v",
                exit_code=0
            )
        )
        
        self.tools['arping'] = ToolMetadata(
            name="arping",
            description="ARP ping tool",
            category=ToolCategory.OPTIONAL,
            required=False,
            detection=ToolDetection(
                command="arping",
                version_flag="-V",
                version_pattern=r"arping ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="arping",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="arping -V",
                exit_code=0
            )
        )
        
        self.tools['fping'] = ToolMetadata(
            name="fping",
            description="Fast ping tool",
            category=ToolCategory.OPTIONAL,
            required=False,
            detection=ToolDetection(
                command="fping",
                version_flag="-v",
                version_pattern=r"fping: Version ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="fping",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="fping -v",
                exit_code=0
            )
        )
        
        self.tools['atk6_inverse_lookup6'] = ToolMetadata(
            name="atk6-inverse_lookup6",
            description="IPv6 reverse lookup",
            category=ToolCategory.OPTIONAL,
            required=False,
            detection=ToolDetection(
                command="atk6-inverse_lookup6",
                version_flag="-h",
                version_pattern=r"Usage"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="thc-ipv6",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="atk6-inverse_lookup6 -h",
                exit_code=0
            )
        )
        
        # Phase 1 Critical Tools
        self.tools['theharvester'] = ToolMetadata(
            name="theHarvester",
            description="OSINT data collection",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="theHarvester",
                version_flag="--version",
                version_pattern=r"([0-9.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="theharvester",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="theHarvester --version",
                exit_code=0
            )
        )
        
        self.tools['burp'] = ToolMetadata(
            name="Burp Suite",
            description="Web application testing",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="burpsuite",
                version_flag="--version",
                version_pattern=r"Burp Suite ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="burpsuite",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="burpsuite --version",
                exit_code=0
            )
        )
        
        self.tools['naabu'] = ToolMetadata(
            name="Naabu",
            description="High-performance port discovery",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="naabu",
                version_flag="-version",
                version_pattern=r"naabu ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.GITHUB,
                repo="projectdiscovery/naabu",
                asset_pattern=r"naabu_.*_linux_amd64\.zip",
                version="2.0+",
                sudo_required=True,
                install_path="/usr/local/bin"
            ),
            validation=ToolValidation(
                test_command="naabu -version",
                exit_code=0
            )
        )
        
        self.tools['katana'] = ToolMetadata(
            name="Katana",
            description="Modern web crawling",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="katana",
                version_flag="-version",
                version_pattern=r"Katana ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.GITHUB,
                repo="projectdiscovery/katana",
                asset_pattern=r"katana_.*_linux_amd64\.zip",
                version="1.0+",
                sudo_required=True,
                install_path="/usr/local/bin"
            ),
            validation=ToolValidation(
                test_command="katana -version",
                exit_code=0
            )
        )
        
        # Phase 1 Remaining Critical Tools
        self.tools['nvd_api'] = ToolMetadata(
            name="NVD API",
            description="CVE metadata and CVSS",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="python3",
                version_flag="--version",
                version_pattern=r"Python ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="requests",
                version="2.31+",
                sudo_required=False
            ),
            validation=ToolValidation(
                test_command="python3 -c \"import requests\"",
                exit_code=0
            )
        )
        
        self.tools['cisa_kev'] = ToolMetadata(
            name="CISA KEV",
            description="Known exploited vulnerabilities",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="cisa-kev",
                version_flag="--version",
                version_pattern=r"cisa-kev ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.GITHUB,
                repo="cisagov/KEV",
                asset_pattern=r"kev_.*_linux_amd64\.tar\.gz",
                version="1.0+",
                sudo_required=True,
                install_path="/usr/local/bin"
            ),
            validation=ToolValidation(
                test_command="cisa-kev --version",
                exit_code=0
            )
        )
        
        self.tools['cvemap'] = ToolMetadata(
            name="CVEMap",
            description="CVE discovery and research",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="cvemap",
                version_flag="-v",
                version_pattern=r"cvemap ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.GITHUB,
                repo="Pwntester/CVEMap",
                asset_pattern=r"cvemap_.*_linux_amd64\.zip",
                version="3.0+",
                sudo_required=True,
                install_path="/usr/local/bin"
            ),
            validation=ToolValidation(
                test_command="cvemap -v",
                exit_code=0
            )
        )
        
        self.tools['pocsuite3'] = ToolMetadata(
            name="Pocsuite3",
            description="PoC development and validation",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="pocsuite3",
                version_flag="--version",
                version_pattern=r"pocsuite3 ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="pocsuite3",
                version="2.0+",
                sudo_required=False
            ),
            validation=ToolValidation(
                test_command="pocsuite3 --version",
                exit_code=0
            )
        )
        
        # Phase 2 Enhanced Capabilities
        self.tools['masscan'] = ToolMetadata(
            name="Masscan",
            description="Large-scale asynchronous scanning",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="masscan",
                version_flag="-V",
                version_pattern=r"masscan ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="masscan",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="masscan -V",
                exit_code=0
            )
        )
        
        self.tools['feroxbuster'] = ToolMetadata(
            name="Feroxbuster",
            description="Recursive content discovery",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="feroxbuster",
                version_flag="-V",
                version_pattern=r"feroxbuster ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.GITHUB,
                repo="epi052/feroxbuster",
                asset_pattern=r"feroxbuster_.*_linux_amd64\.tar\.gz",
                version="2.0+",
                sudo_required=True,
                install_path="/usr/local/bin"
            ),
            validation=ToolValidation(
                test_command="feroxbuster -V",
                exit_code=0
            )
        )
        
        self.tools['ffuf'] = ToolMetadata(
            name="ffuf",
            description="HTTP fuzzing and discovery",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="ffuf",
                version_flag="-V",
                version_pattern=r"ffuf ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.GITHUB,
                repo="ffuf/ffuf",
                asset_pattern=r"ffuf_.*_linux_amd64\.tar\.gz",
                version="2.0+",
                sudo_required=True,
                install_path="/usr/local/bin"
            ),
            validation=ToolValidation(
                test_command="ffuf -V",
                exit_code=0
            )
        )
        
        self.tools['schemathesis'] = ToolMetadata(
            name="Schemathesis",
            description="OpenAPI-driven API property testing",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="schemathesis",
                version_flag="version",
                version_pattern=r"Schemathesis ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="schemathesis",
                version="3.0+",
                sudo_required=False
            ),
            validation=ToolValidation(
                test_command="schemathesis version",
                exit_code=0
            )
        )
        
        self.tools['postman'] = ToolMetadata(
            name="Postman CLI",
            description="API collections and automated workflows",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="newman",
                version_flag="-v",
                version_pattern=r"([0-9.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="newman",
                version="6.0+",
                sudo_required=False
            ),
            validation=ToolValidation(
                test_command="newman -v",
                exit_code=0
            )
        )
        
        self.tools['bandit'] = ToolMetadata(
            name="Bandit",
            description="Python security static analysis",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="bandit",
                version_flag="--version",
                version_pattern=r"bandit ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.PIP,
                package="bandit",
                version="1.7+",
                sudo_required=False
            ),
            validation=ToolValidation(
                test_command="bandit --version",
                exit_code=0
            )
        )
        
        self.tools['linpeas'] = ToolMetadata(
            name="LinPEAS",
            description="Linux privilege escalation exposure discovery",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="linpeas",
                version_flag="-h",
                version_pattern=r"LinPEAS"
            ),
            installation=ToolInstallation(
                type=InstallationType.GITHUB,
                repo="carlospolop/linPEAS",
                asset_pattern=r"linpeas_linux\.sh",
                version="latest",
                sudo_required=True,
                install_path="/usr/local/bin"
            ),
            validation=ToolValidation(
                test_command="linpeas -h",
                exit_code=0
            )
        )
        
        self.tools['lynis'] = ToolMetadata(
            name="Lynis",
            description="Linux security configuration auditing",
            category=ToolCategory.RECOMMENDED,
            required=False,
            detection=ToolDetection(
                command="lynis",
                version_flag="--version",
                version_pattern=r"Lynis ([\d.]+)"
            ),
            installation=ToolInstallation(
                type=InstallationType.APT,
                package="lynis",
                sudo_required=True
            ),
            validation=ToolValidation(
                test_command="lynis --version",
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
