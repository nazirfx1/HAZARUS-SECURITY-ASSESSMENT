"""
HAZARUS theHarvester Integration
OSINT data collection and correlation.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class TheHarvesterResult:
    """theHarvester scan result."""
    target: str
    emails: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    scanned_at: datetime = None
    
    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class TheHarvester:
    """theHarvester OSINT tool integration."""
    
    def __init__(self):
        self.tool_name = "theHarvester"
    
    async def harvest(self, target: str, sources: Optional[List[str]] = None) -> TheHarvesterResult:
        """Harvest OSINT data for a target.
        
        Args:
            target: Target domain or email
            sources: Data sources to use (default: all)
            
        Returns:
            TheHarvesterResult with collected data
        """
        result = TheHarvesterResult(target=target)
        
        try:
            # Check if theHarvester is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "theHarvester",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("theHarvester not installed")
            
            # Build command
            cmd = ["theHarvester", "-d", target]
            
            if sources:
                for source in sources:
                    cmd.extend(["-b", source])
            
            # Execute
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300
            )
            
            # Parse output
            output = stdout.decode()
            
            # Extract emails
            result.emails = self._extract_emails(output)
            
            # Extract domains
            result.domains = self._extract_domains(output)
            
            # Extract subdomains
            result.subdomains = self._extract_subdomains(output)
            
            # Extract IPs
            result.ips = self._extract_ips(output)
            
            # Extract URLs
            result.urls = self._extract_urls(output)
            
        except Exception as e:
            print(f"theHarvester error: {e}")
        
        return result
    
    def _extract_emails(self, output: str) -> List[str]:
        """Extract email addresses from output."""
        import re
        pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
        return list(set(re.findall(pattern, output)))
    
    def _extract_domains(self, output: str) -> List[str]:
        """Extract domains from output."""
        import re
        pattern = r'[\w\.-]+\.\w+'
        return list(set(re.findall(pattern, output)))
    
    def _extract_subdomains(self, output: str) -> List[str]:
        """Extract subdomains from output."""
        import re
        pattern = r'[\w\.-]+\.\w+'
        return list(set(re.findall(pattern, output)))
    
    def _extract_ips(self, output: str) -> List[str]:
        """Extract IP addresses from output."""
        import re
        pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return list(set(re.findall(pattern, output)))
    
    def _extract_urls(self, output: str) -> List[str]:
        """Extract URLs from output."""
        import re
        pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        return list(set(re.findall(pattern, output)))
