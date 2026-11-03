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


@dataclass
class PortConfig:
    """Port configuration settings."""
    dashboard: int = 8000
    zap: int = 8080
    ssl: int = 443
    http: int = 80
    ssh: int = 22
    https: int = 443


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


@dataclass
class PathsConfig:
    """File path configuration settings."""
    temp: str = "/tmp/hazarus"
    backup_dirs: list = field(default_factory=lambda: ["/backup", "/db", "/sql", "/uploads", "/files", "/tmp"])
    cron_dir: str = "/var/spool/cron/crontabs/"
    screenshot_dir: str = "/tmp/hazarus/screenshots"


@dataclass
class DashboardConfig:
    """Dashboard configuration settings."""
    host: str = "127.0.0.1"
    port: int = 8000
    cors_origins: list = field(default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"])
    session_timeout: int = 60


@dataclass
class AssessmentConfig:
    """Assessment configuration settings."""
    intensity: str = "normal"
    rate_limit: int = 100
    request_limit: int = 10000
    max_threads: int = 10
    window: dict = field(default_factory=lambda: {"start": "00:00", "end": "23:59"})


@dataclass
class PrivacyConfig:
    """Privacy configuration settings."""
    require_anonsurf: bool = True
    block_on_dns_leak: bool = True
    block_on_ipv6_exposure: bool = True
    require_tor: bool = False


@dataclass
class LoggingConfig:
    """Logging configuration settings."""
    level: str = "INFO"
    file: str = "~/.hazarus/hazarus.log"
    max_size: int = 100
    backup_count: int = 5


@dataclass
class ReportingConfig:
    """Reporting configuration settings."""
    default_format: str = "markdown"
    include_screenshots: bool = True
    include_detailed_findings: bool = True
    include_asset_inventory: bool = True


@dataclass
class VirtualizationConfig:
    """Virtualization configuration settings."""
    platform: str = "none"
    vmware: dict = field(default_factory=dict)
    virtualbox: dict = field(default_factory=dict)
    libvirt: dict = field(default_factory=dict)


@dataclass
class MetasploitConfig:
    """Metasploit configuration settings."""
    host: str = "127.0.0.1"
    port: int = 55553
    uri: str = "/api/"
    ssl: bool = False
    token: str = ""


@dataclass
class AdvancedConfig:
    """Advanced configuration settings."""
    enable_experimental: bool = False
    debug: bool = False
    verbose: bool = False
    max_retries: int = 3
    retry_delay: int = 5


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
