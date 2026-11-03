"""
HAZARUS Tool Configurer
Configures external tools for HAZARUS integration.
"""

import asyncio
import os
import subprocess
import shutil
from typing import Optional, Dict
from pathlib import Path
from .registry import ToolRegistry, ToolMetadata


class ToolConfigurer:
    """Configures external tools for HAZARUS integration."""
    
    def __init__(self, registry: Optional[ToolRegistry] = None):
        """Initialize tool configurer.
        
        Args:
            registry: Tool registry instance (creates default if None)
        """
        self.registry = registry or ToolRegistry()
        self.config_dir = Path.home() / ".hazarus" / "config"
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    async def configure_tool(self, tool_name: str) -> bool:
        """Configure a tool for HAZARUS integration.
        
        Args:
            tool_name: Name of the tool to configure
            
        Returns:
            True if successful, False otherwise
        """
        tool = self.registry.get_tool(tool_name)
        if not tool or not tool.configuration:
            return True  # No configuration needed
        
        try:
            config = tool.configuration
            
            # Create config file if specified
            if config.config_file:
                await self._create_config_file(tool, config)
            
            # Set environment variables
            if config.environment_vars:
                await self._set_environment_vars(config.environment_vars)
            
            # Create templates directory for Nuclei
            if config.templates_path:
                await self._setup_templates_path(config.templates_path)
            
            return True
            
        except Exception as e:
            print(f"Configuration failed for {tool_name}: {e}")
            return False
    
    async def configure_all(self) -> Dict[str, bool]:
        """Configure all tools.
        
        Returns:
            Dictionary mapping tool names to configuration success
        """
        tools = self.registry.get_all_tools()
        results = {}
        
        for tool_name in tools.keys():
            results[tool_name] = await self.configure_tool(tool_name)
        
        return results
    
    async def _create_config_file(self, tool: ToolMetadata, config):
        """Create configuration file for tool.
        
        Args:
            tool: Tool metadata
            config: Tool configuration
        """
        config_path = self.config_dir / config.config_file
        
        # Generate basic config based on tool type
        if tool.name == "Nuclei":
            config_content = self._generate_nuclei_config(config)
        elif tool.name == "Amass":
            config_content = self._generate_amass_config(config)
        elif tool.name == "Subfinder":
            config_content = self._generate_subfinder_config(config)
        else:
            config_content = f"# {tool.name} configuration\n"
        
        with open(config_path, 'w') as f:
            f.write(config_content)
    
    async def _set_environment_vars(self, env_vars: Dict[str, str]):
        """Set environment variables for tool.
        
        Args:
            env_vars: Dictionary of environment variables
        """
        for key, value in env_vars.items():
            os.environ[key] = value
    
    async def _setup_templates_path(self, templates_path: str):
        """Setup templates directory for Nuclei.
        
        Args:
            templates_path: Path to templates directory
        """
        # Expand ~ to home directory
        templates_path = templates_path.replace("~", str(Path.home()))
        templates_dir = Path(templates_path)
        templates_dir.mkdir(parents=True, exist_ok=True)
        
        # Download basic templates if empty
        if not any(templates_dir.iterdir()):
            await self._download_nuclei_templates(templates_dir)
    
    async def _download_nuclei_templates(self, templates_dir: Path):
        """Download basic Nuclei templates.
        
        Args:
            templates_dir: Directory to download templates to
        """
        try:
            import httpx
            
            # Download nuclei-templates
            url = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"
            zip_path = self.config_dir / "nuclei-templates.zip"
            
            async with httpx.AsyncClient(timeout=300) as client:
                async with client.stream('GET', url) as response:
                    response.raise_for_status()
                    
                    with open(zip_path, 'wb') as f:
                        async for chunk in response.aiter_bytes():
                            f.write(chunk)
            
            # Extract
            import zipfile
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(self.config_dir)
            
            # Move templates to target directory
            extracted_dir = self.config_dir / "nuclei-templates-main"
            if extracted_dir.exists():
                for item in extracted_dir.iterdir():
                    if item.is_dir():
                        shutil.copytree(item, templates_dir / item.name, dirs_exist_ok=True)
                    else:
                        shutil.copy2(item, templates_dir / item.name)
            
            # Cleanup
            zip_path.unlink()
            shutil.rmtree(extracted_dir, ignore_errors=True)
            
        except Exception as e:
            print(f"Failed to download Nuclei templates: {e}")
    
    def _generate_nuclei_config(self, config) -> str:
        """Generate Nuclei configuration.
        
        Args:
            config: Tool configuration
            
        Returns:
            Configuration file content
        """
        return f"""# Nuclei Configuration for HAZARUS
# Templates directory
templates-directory: {config.templates_path}

# Rate limiting
rate-limit: 100
bulk-size: 25

# Timeout
timeout: 30

# Severity
severity: critical,high,medium,low,info

# Exclude
exclude:
  - staging
  - dev
  - test
"""
    
    def _generate_amass_config(self, config) -> str:
        """Generate Amass configuration.
        
        Args:
            config: Tool configuration
            
        Returns:
            Configuration file content
        """
        return f"""# Amass Configuration for HAZARUS
# Data directory
amass:
  directory: ~/.config/amass

# Data sources
datasources:
  - crtsh
  - rabcdns
  - s3
  - shodan
  - forward
  - reverse
"""
    
    def _generate_subfinder_config(self, config) -> str:
        """Generate Subfinder configuration.
        
        Args:
            config: Tool configuration
            
        Returns:
            Configuration file content
        """
        return f"""# Subfinder Configuration for HAZARUS
# API keys (add your own)
subfinder:
  - tcs
  - crtsh
  - certspotter
  - securitytrails
  - virustotal

# Rate limiting
threads: 10
timeout: 30
"""
