"""
HAZARUS Advanced Web Tools
Integration with Parrot OS web security tools: wpscan, whatweb, gobuster, websploit.
"""

import asyncio
import logging
import re
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class WPScanResult:
    """WPScan result for WordPress sites."""
    target: str
    is_wordpress: bool = False
    version: Optional[str] = None
    plugins: List[str] = field(default_factory=list)
    themes: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class WhatWebResult:
    """WhatWeb technology detection result."""
    target: str
    technologies: List[str] = field(default_factory=list)
    version_info: Dict[str, str] = field(default_factory=dict)
    server: Optional[str] = None
    errors: List[str] = field(default_factory=list)


@dataclass
class GobusterResult:
    """Gobuster directory brute force result."""
    target: str
    directories: List[str] = field(default_factory=list)
    status_codes: Dict[str, int] = field(default_factory=dict)
    total_found: int = 0
    errors: List[str] = field(default_factory=list)


@dataclass
class WebExploitResult:
    """WebExploit framework result."""
    target: str
    exploits: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class AdvancedWebTools:
    """Advanced web security tools integration for Parrot OS."""

    def __init__(self, timeout: int = 600):
        self.timeout = timeout
        self.logger = logging.getLogger("hazarus.advanced_web_tools")

    async def wpscan_scan(self, target: str, aggressive: bool = False) -> WPScanResult:
        """Scan WordPress sites with WPScan."""
        result = WPScanResult(target=target)

        try:
            # Check if wpscan is available
            proc = await asyncio.create_subprocess_exec(
                "which", "wpscan",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()

            if proc.returncode != 0:
                self.logger.info("wpscan not available, skipping WordPress scan")
                result.errors.append("wpscan not installed")
                return result

            self.logger.info(f"Running WPScan for {target}")

            # Build wpscan command with improved error handling
            cmd = ["wpscan", "--url", target, "--no-update", "--enumerate", "--no-banner"]
            
            if aggressive:
                cmd.extend(["--plugins-detection", "aggressive", "--themes-detection", "aggressive"])
            else:
                cmd.extend(["--plugins-detection", "vp", "--themes-detection", "vt"])

            # Add timeout and rate limiting
            cmd.extend(["--request-timeout", "30"])  # 30 second timeout per request

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                self.logger.warning("WPScan timed out")
                result.errors.append("Scan timed out after " + str(self.timeout) + " seconds")
                return result

            output = stdout.decode()
            stderr_text = stderr.decode()

            # WPScan returns non-zero even on success sometimes, check output
            if "WordPress" in output or output.strip():
                # Parse WPScan output
                result.is_wordpress = "WordPress" in output

                # Extract version
                version_match = re.search(r'WordPress version ([\d.]+)', output)
                if version_match:
                    result.version = version_match.group(1)

                # Extract plugins
                plugin_matches = re.findall(r'plugin: ([^\s]+)', output)
                result.plugins = list(set(plugin_matches))

                # Extract themes
                theme_matches = re.findall(r'theme: ([^\s]+)', output)
                result.themes = list(set(theme_matches))

                # Extract vulnerabilities
                vuln_pattern = r'CVE-\d{4}-\d+'
                result.vulnerabilities = list(set(re.findall(vuln_pattern, output)))

                self.logger.info(f"WPScan found {len(result.plugins)} plugins, {len(result.themes)} themes")
            else:
                self.logger.warning(f"WPScan failed: {stderr_text}")
                result.errors.append(f"WPScan error: {stderr_text[:200]}")  # Truncate long errors

        except Exception as e:
            self.logger.error(f"WPScan failed: {e}")
            result.errors.append(str(e))

        return result

    async def whatweb_scan(self, target: str, aggressive: bool = False) -> WhatWebResult:
        """Detect web technologies with WhatWeb."""
        result = WhatWebResult(target=target)

        try:
            # Check if whatweb is available
            proc = await asyncio.create_subprocess_exec(
                "which", "whatweb",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()

            if proc.returncode != 0:
                self.logger.info("whatweb not available, skipping technology detection")
                result.errors.append("whatweb not installed")
                return result

            self.logger.info(f"Running WhatWeb for {target}")

            # Build whatweb command
            cmd = ["whatweb", "--log-json", "/dev/stdout", target]
            
            if aggressive:
                cmd.append("-a")  # Aggressive mode

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                self.logger.warning("WhatWeb timed out")
                result.errors.append("Scan timed out")
                return result

            output = stdout.decode()
            stderr_text = stderr.decode()

            if proc.returncode != 0:
                self.logger.warning(f"WhatWeb failed: {stderr_text}")
                result.errors.append(stderr_text)
                return result

            # Parse WhatWeb JSON output
            try:
                import json
                data = json.loads(output)
                
                if isinstance(data, list) and len(data) > 0:
                    data = data[0]

                # Extract technologies
                if "plugins" in data:
                    for plugin in data["plugins"]:
                        if isinstance(plugin, dict):
                            name = plugin.get("name", "")
                            version = plugin.get("version", "")
                            if name:
                                result.technologies.append(name)
                                if version:
                                    result.version_info[name] = version

                # Extract server
                if "Server" in data:
                    result.server = data["Server"]

                self.logger.info(f"WhatWeb found {len(result.technologies)} technologies")

            except json.JSONDecodeError:
                # Fallback to plain text parsing - improved regex
                # Match patterns like "WordPress, PHP, Nginx, etc."
                tech_pattern = r'([A-Z][a-zA-Z0-9]+(?:\s+[\d.]+)?)'
                result.technologies = list(set(re.findall(tech_pattern, output)))
                self.logger.warning("Could not parse WhatWeb JSON, using fallback parsing")
                
                # Also try to extract server from plain text
                server_match = re.search(r'Server:\s+([^\s]+)', output)
                if server_match:
                    result.server = server_match.group(1)

        except Exception as e:
            self.logger.error(f"WhatWeb failed: {e}")
            result.errors.append(str(e))

        return result

    async def gobuster_scan(
        self,
        target: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        aggressive: bool = False
    ) -> GobusterResult:
        """Directory brute force with Gobuster."""
        result = GobusterResult(target=target)

        try:
            # Check if gobuster is available
            proc = await asyncio.create_subprocess_exec(
                "which", "gobuster",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()

            if proc.returncode != 0:
                self.logger.info("gobuster not available, skipping directory brute force")
                result.errors.append("gobuster not installed")
                return result

            self.logger.info(f"Running Gobuster for {target}")

            # Build gobuster command with reduced thread count
            cmd = [
                "gobuster", "dir",
                "-u", target,
                "-w", wordlist,
                "-t", "20",  # Reduced from 50 to 20 to prevent connection resets
                "-x", "php,html,js,css,txt,xml",
                "-k",  # Skip SSL verification
                "--timeout", "30s"  # Increased from 10s to 30s
            ]

            if aggressive:
                cmd.extend(["-f", "-q"])  # Force mode, quiet output

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                self.logger.warning("Gobuster timed out")
                result.errors.append("Scan timed out")
                return result

            output = stdout.decode()
            stderr_text = stderr.decode()

            if proc.returncode != 0:
                self.logger.warning(f"Gobuster failed: {stderr_text}")
                result.errors.append(stderr_text)
                return result

            # Parse Gobuster output
            # Format: "https://example.com/admin (Status: 200) [Size: 1234]"
            for line in output.split('\n'):
                match = re.search(r'([^\s]+)\s+\(Status:\s+(\d+)\)', line)
                if match:
                    directory = match.group(1)
                    status_code = match.group(2)
                    
                    result.directories.append(directory)
                    result.status_codes[status_code] = result.status_codes.get(status_code, 0) + 1

            result.total_found = len(result.directories)
            self.logger.info(f"Gobuster found {result.total_found} directories")

        except Exception as e:
            self.logger.error(f"Gobuster failed: {e}")
            result.errors.append(str(e))

        return result

    async def websploit_scan(self, target: str) -> WebExploitResult:
        """WebExploit framework integration (read-only vulnerability search)."""
        result = WebExploitResult(target=target)

        try:
            # Check if websploit is available
            proc = await asyncio.create_subprocess_exec(
                "which", "websploit",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()

            if proc.returncode != 0:
                self.logger.info("websploit not available, skipping exploit search")
                result.errors.append("websploit not installed")
                return result

            self.logger.info(f"Running WebExploit search for {target}")

            # WebExploit is interactive and often doesn't support search commands
            # Skip this if not critical for the assessment
            self.logger.info("WebExploit: Tool integration skipped (not suitable for automated scanning)")
            result.errors.append("WebExploit skipped - tool requires interactive use")
            return result

        except Exception as e:
            self.logger.error(f"WebExploit failed: {e}")
            result.errors.append(str(e))

        return result

    def to_dict(self, result: Any) -> Dict[str, Any]:
        """Convert result to dictionary."""
        if isinstance(result, WPScanResult):
            return {
                "target": result.target,
                "is_wordpress": result.is_wordpress,
                "version": result.version,
                "plugins": result.plugins,
                "themes": result.themes,
                "vulnerabilities": result.vulnerabilities,
                "errors": result.errors
            }
        elif isinstance(result, WhatWebResult):
            return {
                "target": result.target,
                "technologies": result.technologies,
                "version_info": result.version_info,
                "server": result.server,
                "errors": result.errors
            }
        elif isinstance(result, GobusterResult):
            return {
                "target": result.target,
                "directories": result.directories,
                "status_codes": result.status_codes,
                "total_found": result.total_found,
                "errors": result.errors
            }
        elif isinstance(result, WebExploitResult):
            return {
                "target": result.target,
                "exploits": result.exploits,
                "vulnerabilities": result.vulnerabilities,
                "errors": result.errors
            }
        return {}
