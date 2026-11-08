"""
HAZARUS Configuration Manager
Centralized configuration loading and management.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class LabConfig:
    """Lab configuration settings."""
    cidr_ranges: list = field(default_factory=lambda: ["192.168.100.0/24", "10.0.100.0/24"])
    targets: list = field(default_factory=list)

    def __init__(self, **kwargs):
        # Initialize with defaults, then update with provided kwargs
        self.cidr_ranges = kwargs.get("cidr_ranges", ["192.168.100.0/24", "10.0.100.0/24"])
        self.targets = kwargs.get("targets", [])
        # Store any extra fields to avoid errors
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)


@dataclass
class TimeoutConfig:
    """Timeout configuration settings."""
    default: int = 30
    quick: int = 10
    long: int = 600
    exploitation: int = 300
    code_analysis: int = 300
    subdomain_discovery: int = 300
    advanced_subdomain: int = 600
    live_discovery: int = 60
    dns: int = 30
    ssl: int = 30
    api: int = 30
    http_scan: int = 30
    advanced_web: int = 600
    password_cracking: int = 3600
    reverse_engineering: int = 300
    wireless: int = 300
    ai: int = 300
    download: int = 300
    post_assessment: int = 600
    kev_due_days: int = 30

    def __init__(self, **kwargs):
        # Initialize with defaults, then update with provided kwargs
        self.default = kwargs.get("default", 30)
        self.quick = kwargs.get("quick", 10)
        self.long = kwargs.get("long", 600)
        self.exploitation = kwargs.get("exploitation", 300)
        self.code_analysis = kwargs.get("code_analysis", 300)
        self.subdomain_discovery = kwargs.get("subdomain_discovery", 300)
        self.advanced_subdomain = kwargs.get("advanced_subdomain", 600)
        self.live_discovery = kwargs.get("live_discovery", 60)
        self.dns = kwargs.get("dns", 30)
        self.ssl = kwargs.get("ssl", 30)
        self.api = kwargs.get("api", 30)
        self.http_scan = kwargs.get("http_scan", 30)
        self.advanced_web = kwargs.get("advanced_web", 600)
        self.password_cracking = kwargs.get("password_cracking", 3600)
        self.reverse_engineering = kwargs.get("reverse_engineering", 300)
        self.wireless = kwargs.get("wireless", 300)
        self.ai = kwargs.get("ai", 300)
        self.download = kwargs.get("download", 300)
        self.post_assessment = kwargs.get("post_assessment", 600)
        self.kev_due_days = kwargs.get("kev_due_days", 30)
        # Store any extra fields to avoid errors
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)


@dataclass
class PortConfig:
    """Port configuration settings."""
    dashboard: int = 8000
    zap: int = 8080
    ssl: int = 443
    http: int = 80
    https: int = 443
    ssh: int = 22
    common_ports: list = field(default_factory=lambda: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443])
    success_status_codes: list = field(default_factory=lambda: [200, 301, 302, 304, 307, 308])

    def __init__(self, **kwargs):
        # Initialize with defaults, then update with provided kwargs
        self.dashboard = kwargs.get("dashboard", 8000)
        self.zap = kwargs.get("zap", 8080)
        self.ssl = kwargs.get("ssl", 443)
        self.http = kwargs.get("http", 80)
        self.https = kwargs.get("https", 443)
        self.ssh = kwargs.get("ssh", 22)
        self.common_ports = kwargs.get("common_ports", [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443])
        self.success_status_codes = kwargs.get("success_status_codes", [200, 301, 302, 304, 307, 308])
        # Store any extra fields to avoid errors
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)


@dataclass
class APIEndpointsConfig:
    """API endpoint configuration settings."""
    securitytrails: str = "https://api.securitytrails.com/v1"
    shodan: str = "https://api.shodan.io/shodan"
    censys: str = "https://search.censys.io/api/v2"
    virustotal: str = "https://www.virustotal.com/api/v3"
    github: str = "https://api.github.com"
    nvd: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    ssllabs: str = "https://api.ssllabs.com/api/v3"

    def __init__(self, **kwargs):
        # Initialize with defaults, then update with provided kwargs
        self.securitytrails = kwargs.get("securitytrails", "https://api.securitytrails.com/v1")
        self.shodan = kwargs.get("shodan", "https://api.shodan.io/shodan")
        self.censys = kwargs.get("censys", "https://search.censys.io/api/v2")
        self.virustotal = kwargs.get("virustotal", "https://www.virustotal.com/api/v3")
        self.github = kwargs.get("github", "https://api.github.com")
        self.nvd = kwargs.get("nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.ssllabs = kwargs.get("ssllabs", "https://api.ssllabs.com/api/v3")
        # Store any extra fields to avoid errors
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)


@dataclass
class PathsConfig:
    """File path configuration settings."""
    temp: str = "/tmp/hazarus"
    backup_dirs: list = field(default_factory=lambda: ["/backup", "/db", "/sql", "/uploads", "/files", "/tmp"])
    cron_dir: str = "/var/spool/cron/crontabs/"
    screenshot_dir: str = "/tmp/hazarus/screenshots"

    def __init__(self, **kwargs):
        # Initialize with defaults, then update with provided kwargs
        self.temp = kwargs.get("temp", "/tmp/hazarus")
        self.backup_dirs = kwargs.get("backup_dirs", ["/backup", "/db", "/sql", "/uploads", "/files", "/tmp"])
        self.cron_dir = kwargs.get("cron_dir", "/var/spool/cron/crontabs/")
        self.screenshot_dir = kwargs.get("screenshot_dir", "/tmp/hazarus/screenshots")
        # Store any extra fields to avoid errors
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)


@dataclass
class DashboardConfig:
    """Dashboard configuration settings."""
    host: str = "127.0.0.1"
    port: int = 8000
    cors_origins: list = field(default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"])
    session_timeout: int = 60

    def __init__(self, **kwargs):
        # Initialize with defaults, then update with provided kwargs
        self.host = kwargs.get("host", "127.0.0.1")
        self.port = kwargs.get("port", 8000)
        self.cors_origins = kwargs.get("cors_origins", ["http://localhost:3000", "http://127.0.0.1:3000"])
        self.session_timeout = kwargs.get("session_timeout", 60)
        # Store any extra fields to avoid errors
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)


@dataclass
class AssessmentConfig:
    """Assessment configuration settings."""
    intensity: str = "normal"
    rate_limit: int = 100
    request_limit: int = 10000
    max_threads: int = 10
    window: dict = field(default_factory=lambda: {"start": "00:00", "end": "23:59"})
    wordlists: dict = field(default_factory=lambda: {"subdomains": "", "directories": "", "passwords": "", "usernames": ""})
    privacy_mode: str = "standard"
    timeout: int = 30
    
    def __init__(self, **kwargs):
        # Initialize with defaults, then update with provided kwargs
        self.intensity = kwargs.get("intensity", "normal")
        self.rate_limit = kwargs.get("rate_limit", 100)
        self.request_limit = kwargs.get("request_limit", 10000)
        self.max_threads = kwargs.get("max_threads", 10)
        self.window = kwargs.get("window", {"start": "00:00", "end": "23:59"})
        self.wordlists = kwargs.get("wordlists", {"subdomains": "", "directories": "", "passwords": "", "usernames": ""})
        self.privacy_mode = kwargs.get("privacy_mode", "standard")
        self.timeout = kwargs.get("timeout", 30)
        # Store any extra fields to avoid errors
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)


@dataclass
class PrivacyConfig:
    """Privacy configuration settings."""
    require_anonsurf: bool = True
    block_on_dns_leak: bool = True
    block_on_ipv6_exposure: bool = True
    require_tor: bool = False

    def __init__(self, **kwargs):
        # Initialize with defaults, then update with provided kwargs
        self.require_anonsurf = kwargs.get("require_anonsurf", True)
        self.block_on_dns_leak = kwargs.get("block_on_dns_leak", True)
        self.block_on_ipv6_exposure = kwargs.get("block_on_ipv6_exposure", True)
        self.require_tor = kwargs.get("require_tor", False)
        # Store any extra fields to avoid errors
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)


@dataclass
class LoggingConfig:
    """Logging configuration settings."""
    level: str = "INFO"
    file: str = "~/.hazarus/hazarus.log"
    max_size: int = 100
    backup_count: int = 5

    def __init__(self, **kwargs):
        # Initialize with defaults, then update with provided kwargs
        self.level = kwargs.get("level", "INFO")
        self.file = kwargs.get("file", "~/.hazarus/hazarus.log")
        self.max_size = kwargs.get("max_size", 100)
        self.backup_count = kwargs.get("backup_count", 5)
        # Store any extra fields to avoid errors
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)


@dataclass
class ReportingConfig:
    """Reporting configuration settings."""
    default_format: str = "markdown"
    include_screenshots: bool = True
    include_detailed_findings: bool = True
    include_asset_inventory: bool = True

    def __init__(self, **kwargs):
        # Initialize with defaults, then update with provided kwargs
        self.default_format = kwargs.get("default_format", "markdown")
        self.include_screenshots = kwargs.get("include_screenshots", True)
        self.include_detailed_findings = kwargs.get("include_detailed_findings", True)
        self.include_asset_inventory = kwargs.get("include_asset_inventory", True)
        # Store any extra fields to avoid errors
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)


@dataclass
class VirtualizationConfig:
    """Virtualization configuration settings."""
    platform: str = "none"
    vmware: dict = field(default_factory=dict)
    virtualbox: dict = field(default_factory=dict)
    libvirt: dict = field(default_factory=dict)

    def __init__(self, **kwargs):
        # Initialize with defaults, then update with provided kwargs
        self.platform = kwargs.get("platform", "none")
        self.vmware = kwargs.get("vmware", {})
        self.virtualbox = kwargs.get("virtualbox", {})
        self.libvirt = kwargs.get("libvirt", {})
        # Store any extra fields to avoid errors
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)


@dataclass
class MetasploitConfig:
    """Metasploit configuration settings."""
    host: str = "127.0.0.1"
    port: int = 55553
    uri: str = "/api/"
    ssl: bool = False
    token: str = ""

    def __init__(self, **kwargs):
        # Initialize with defaults, then update with provided kwargs
        self.host = kwargs.get("host", "127.0.0.1")
        self.port = kwargs.get("port", 55553)
        self.uri = kwargs.get("uri", "/api/")
        self.ssl = kwargs.get("ssl", False)
        self.token = kwargs.get("token", "")
        # Store any extra fields to avoid errors
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)


@dataclass
class AdvancedConfig:
    """Advanced configuration settings."""
    enable_experimental: bool = False
    debug: bool = False
    verbose: bool = False
    max_retries: int = 3
    retry_delay: int = 5

    def __init__(self, **kwargs):
        # Initialize with defaults, then update with provided kwargs
        self.enable_experimental = kwargs.get("enable_experimental", False)
        self.debug = kwargs.get("debug", False)
        self.verbose = kwargs.get("verbose", False)
        self.max_retries = kwargs.get("max_retries", 3)
        self.retry_delay = kwargs.get("retry_delay", 5)
        # Store any extra fields to avoid errors
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)


@dataclass
class HazarusConfig:
    """Main HAZARUS configuration."""
    lab: LabConfig = field(default_factory=LabConfig)
    timeouts: TimeoutConfig = field(default_factory=TimeoutConfig)
    ports: PortConfig = field(default_factory=PortConfig)
    api_endpoints: APIEndpointsConfig = field(default_factory=APIEndpointsConfig)
    paths: PathsConfig = field(default_factory=PathsConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    assessment: AssessmentConfig = field(default_factory=AssessmentConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    virtualization: VirtualizationConfig = field(default_factory=VirtualizationConfig)
    metasploit: MetasploitConfig = field(default_factory=MetasploitConfig)
    advanced: AdvancedConfig = field(default_factory=AdvancedConfig)


class ConfigManager:
    """
    Configuration manager for HAZARUS framework.
    Loads and provides access to configuration settings.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_path: Path to configuration file. If None, uses default locations.
        """
        self.config_path = self._resolve_config_path(config_path)
        self.config: Optional[HazarusConfig] = None
        self._raw_config: Dict[str, Any] = {}

    def _resolve_config_path(self, config_path: Optional[str]) -> Path:
        """
        Resolve configuration file path.
        
        Args:
            config_path: User-provided config path or None
            
        Returns:
            Path to configuration file
        """
        if config_path:
            return Path(config_path)
        
        # Check project config directory first
        project_config = Path.cwd() / "config" / "hazarus.yaml"
        if project_config.exists():
            return project_config
        
        # Check user home directory
        home_config = Path.home() / ".hazarus" / "config" / "hazarus.yaml"
        if home_config.exists():
            return home_config
        
        # Default to project config
        return project_config

    def load(self) -> HazarusConfig:
        """
        Load configuration from file.
        
        Returns:
            HazarusConfig object with loaded settings
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If config file is invalid
        """
        if not self.config_path.exists():
            # Return default configuration if file doesn't exist
            self.config = HazarusConfig()
            self._raw_config = {}
            return self.config
        
        with open(self.config_path, "r") as f:
            self._raw_config = yaml.safe_load(f) or {}
        
        # Parse configuration into dataclasses
        self.config = self._parse_config(self._raw_config)
        
        return self.config

    def _parse_config(self, raw: Dict[str, Any]) -> HazarusConfig:
        """
        Parse raw configuration dictionary into HazarusConfig.
        
        Args:
            raw: Raw configuration dictionary
            
        Returns:
            HazarusConfig object
        """
        return HazarusConfig(
            lab=LabConfig(**raw.get("lab", {})),
            timeouts=TimeoutConfig(**raw.get("timeouts", {})),
            ports=PortConfig(**raw.get("ports", {})),
            api_endpoints=APIEndpointsConfig(**raw.get("api_endpoints", {})),
            paths=PathsConfig(**raw.get("paths", {})),
            dashboard=DashboardConfig(**raw.get("dashboard", {})),
            assessment=AssessmentConfig(**raw.get("assessment", {})),
            privacy=PrivacyConfig(**raw.get("privacy", {})),
            logging=LoggingConfig(**raw.get("logging", {})),
            reporting=ReportingConfig(**raw.get("reporting", {})),
            virtualization=VirtualizationConfig(**raw.get("virtualization", {})),
            metasploit=MetasploitConfig(**raw.get("metasploit", {})),
            advanced=AdvancedConfig(**raw.get("advanced", {}))
        )

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by dot-notation key.
        
        Args:
            key: Configuration key in dot notation (e.g., "timeouts.default")
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        if not self.config:
            self.load()
        
        keys = key.split(".")
        value = self._raw_config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        
        return value if value is not None else default

    def save(self, config: Optional[HazarusConfig] = None) -> None:
        """
        Save configuration to file.
        
        Args:
            config: Configuration to save. If None, saves current config.
        """
        if config:
            self.config = config
        
        if not self.config:
            raise ValueError("No configuration to save")
        
        # Convert dataclasses to dictionaries
        raw_config = {
            "lab": self.config.lab.__dict__,
            "timeouts": self.config.timeouts.__dict__,
            "ports": self.config.ports.__dict__,
            "api_endpoints": self.config.api_endpoints.__dict__,
            "paths": self.config.paths.__dict__,
            "dashboard": self.config.dashboard.__dict__,
            "assessment": self.config.assessment.__dict__,
            "privacy": self.config.privacy.__dict__,
            "logging": self.config.logging.__dict__,
            "reporting": self.config.reporting.__dict__,
            "virtualization": self.config.virtualization.__dict__,
            "metasploit": self.config.metasploit.__dict__,
            "advanced": self.config.advanced.__dict__
        }
        
        # Ensure directory exists
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.config_path, "w") as f:
            yaml.dump(raw_config, f, default_flow_style=False)

    def reload(self) -> HazarusConfig:
        """
        Reload configuration from file.
        
        Returns:
            Reloaded HazarusConfig object
        """
        return self.load()


# Global configuration instance
_global_config: Optional[ConfigManager] = None


def get_config(config_path: Optional[str] = None) -> ConfigManager:
    """
    Get global configuration manager instance.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        ConfigManager instance
    """
    global _global_config
    
    if _global_config is None:
        _global_config = ConfigManager(config_path)
        _global_config.load()
    
    return _global_config


def reset_config() -> None:
    """Reset global configuration instance (useful for testing)."""
    global _global_config
    _global_config = None
