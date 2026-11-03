"""
HAZARUS SpiderFoot Integration
Automated OSINT correlation.
"""

import asyncio
import subprocess
import json
import re
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime

from core.config import get_config
config = get_config()


@dataclass
class SpiderFootResult:
    """SpiderFoot scan result."""
    target: str
    data_types: List[str] = field(default_factory=list)
    total_entities: int = 0
    correlated_data: Dict[str, List] = field(default_factory=dict)
    domain_names: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    social_media: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    breach_data: List[Dict] = field(default_factory=list)
    reputation_scores: Dict[str, float] = field(default_factory=dict)
    scan_duration: Optional[float] = None
    modules_used: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    scanned_at: datetime = None
    
    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class SpiderFootScanner:
    """SpiderFoot integration for OSINT correlation."""
    
    def __init__(self):
        self.tool_name = "spiderfoot"
    
    async def scan(self, target: str, modules: Optional[List[str]] = None) -> SpiderFootResult:
        """Scan target with SpiderFoot.
        
        Args:
            target: Target domain or IP
            modules: List of modules to use
            
        Returns:
            SpiderFootResult with correlated OSINT data
        """
        result = SpiderFootResult(target=target)
        
        try:
            # Check if spiderfoot is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "sf",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("SpiderFoot not installed")
            
            # Build command
            cmd = ["sf", "-s", target]
            
            if modules:
                cmd.extend(["-m", ",".join(modules)])
            
            # Execute
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=config.get('timeouts.subdomain_discovery', 600)
            )
            
            # Parse output
            output = stdout.decode()
            result = self._parse_output(output, target)
            
        except Exception as e:
            print(f"SpiderFoot error: {e}")
        
        return result
    
    def _parse_output(self, output: str, target: str) -> SpiderFootResult:
        """Parse SpiderFoot output.
        
        Handles multiple output formats:
        - JSON output (preferred)
        - Table/formatted text output
        - Structured log output
        """
        result = SpiderFootResult(target=target)
        
        if not output or not output.strip():
            return result
        
        # Try JSON parsing first
        try:
            if output.strip().startswith('{') or output.strip().startswith('['):
                data = json.loads(output)
                
                # Handle scan result object
                if isinstance(data, dict):
                    self._parse_spiderfoot_json(data, result)
                # Handle array of results
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            self._parse_spiderfoot_json(item, result)
                
                return result
        except json.JSONDecodeError:
            pass
        
        # Parse text/table output
        lines = output.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Detect section headers
            if line.endswith(':') and not line.startswith('['):
                current_section = line.rstrip(':').lower()
                continue
            
            # Parse based on section
            if current_section:
                if 'entity' in current_section or 'data type' in current_section:
                    # Extract data types
                    if line and not line.startswith('-'):
                        data_type = line.split()[0] if line.split() else line
                        if data_type not in result.data_types:
                            result.data_types.append(data_type)
                
                elif 'domain' in current_section:
                    # Extract domain names
                    domain_match = re.search(r'([a-zA-Z0-9][\w-]*\.[a-zA-Z]{2,})', line)
                    if domain_match:
                        domain = domain_match.group(1).lower()
                        if domain not in result.domain_names:
                            result.domain_names.append(domain)
                
                elif 'ip' in current_section or 'address' in current_section:
                    # Extract IP addresses
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        if ip not in result.ip_addresses:
                            result.ip_addresses.append(ip)
                
                elif 'email' in current_section:
                    # Extract email addresses
                    email_match = re.search(r'([\w\.-]+@[\w\.-]+\.\w+)', line)
                    if email_match:
                        email = email_match.group(1).lower()
                        if email not in result.email_addresses:
                            result.email_addresses.append(email)
                
                elif 'phone' in current_section or 'telephone' in current_section:
                    # Extract phone numbers
                    phone_match = re.search(r'(\+?[\d\s\-\(\)]{10,})', line)
                    if phone_match:
                        phone = phone_match.group(1)
                        if phone not in result.phone_numbers:
                            result.phone_numbers.append(phone)
                
                elif 'social' in current_section or 'profile' in current_section:
                    # Extract social media profiles
                    social_match = re.search(r'(twitter|facebook|linkedin|instagram|github|reddit)[^\s]*', line, re.IGNORECASE)
                    if social_match:
                        social = social_match.group(0)
                        if social not in result.social_media:
                            result.social_media.append(social)
                
                elif 'vulnerability' in current_section or 'cve' in current_section:
                    # Extract vulnerability information
                    cve_match = re.search(r'(CVE-\d{4}-\d{4,})', line)
                    if cve_match:
                        vuln = {'cve_id': cve_match.group(1)}
                        # Try to extract CVSS score
                        cvss_match = re.search(r'CVSS[:\s]+(\d+\.?\d*)', line, re.IGNORECASE)
                        if cvss_match:
                            vuln['cvss_score'] = float(cvss_match.group(1))
                        result.vulnerabilities.append(vuln)
                
                elif 'breach' in current_section or 'leak' in current_section:
                    # Extract breach data
                    breach = {'source': 'unknown', 'description': line}
                    date_match = re.search(r'(\d{4}-\d{2}-\d{2})', line)
                    if date_match:
                        breach['date'] = date_match.group(1)
                    result.breach_data.append(breach)
                
                elif 'reputation' in current_section or 'score' in current_section:
                    # Extract reputation scores
                    score_match = re.search(r'(\w+)[:\s]+(\d+\.?\d*)', line)
                    if score_match:
                        source = score_match.group(1)
                        score = float(score_match.group(2))
                        result.reputation_scores[source] = score
                
                elif 'module' in current_section:
                    # Extract modules used
                    if line and not line.startswith('-'):
                        module = line.strip()
                        if module not in result.modules_used:
                            result.modules_used.append(module)
            
            # General entity counting
            if 'entity' in line.lower():
                count_match = re.search(r'(\d+)\s*entities?', line, re.IGNORECASE)
                if count_match:
                    result.total_entities = int(count_match.group(1))
                else:
                    result.total_entities += 1
            
            # Extract duration
            duration_match = re.search(r'duration[:\s]+(\d+\.?\d*)\s*(seconds?|minutes?|hours?)', line, re.IGNORECASE)
            if duration_match:
                duration = float(duration_match.group(1))
                unit = duration_match.group(2).lower()
                if unit.startswith('min'):
                    duration *= 60
                elif unit.startswith('hour'):
                    duration *= 3600
                result.scan_duration = duration
            
            # Extract warnings
            if line.lower().startswith(('warning', 'warn', 'error', 'fail')):
                result.warnings.append(line)
            
            # Generic extraction for correlated data
            if ':' in line and '=' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                if key and value:
                    if key not in result.correlated_data:
                        result.correlated_data[key] = []
                    result.correlated_data[key].append(value)
        
        # Post-processing: extract additional data from correlated_data
        self._extract_from_correlated_data(result)
        
        return result
    
    def _parse_spiderfoot_json(self, data: Dict, result: SpiderFootResult):
        """Parse SpiderFoot data from JSON object."""
        # Extract modules used
        modules = data.get('modules') or data.get('modules_used')
        if modules:
            if isinstance(modules, list):
                result.modules_used = modules
            elif isinstance(modules, str):
                result.modules_used = [m.strip() for m in modules.split(',')]
        
        # Extract entity count
        result.total_entities = data.get('entity_count') or data.get('total_entities', 0)
        
        # Extract data types
        data_types = data.get('data_types') or data.get('types')
        if data_types:
            if isinstance(data_types, list):
                result.data_types = data_types
            elif isinstance(data_types, str):
                result.data_types = [dt.strip() for dt in data_types.split(',')]
        
        # Extract domain names
        domains = data.get('domains') or data.get('domain_names')
        if domains:
            if isinstance(domains, list):
                result.domain_names = domains
            elif isinstance(domains, str):
                result.domain_names = [d.strip() for d in domains.split(',')]
        
        # Extract IP addresses
        ips = data.get('ips') or data.get('ip_addresses')
        if ips:
            if isinstance(ips, list):
                result.ip_addresses = ips
            elif isinstance(ips, str):
                result.ip_addresses = [ip.strip() for ip in ips.split(',')]
        
        # Extract email addresses
        emails = data.get('emails') or data.get('email_addresses')
        if emails:
            if isinstance(emails, list):
                result.email_addresses = emails
            elif isinstance(emails, str):
                result.email_addresses = [e.strip() for e in emails.split(',')]
        
        # Extract phone numbers
        phones = data.get('phones') or data.get('phone_numbers')
        if phones:
            if isinstance(phones, list):
                result.phone_numbers = phones
            elif isinstance(phones, str):
                result.phone_numbers = [p.strip() for p in phones.split(',')]
        
        # Extract social media
        social = data.get('social') or data.get('social_media')
        if social:
            if isinstance(social, list):
                result.social_media = social
            elif isinstance(social, str):
                result.social_media = [s.strip() for s in social.split(',')]
        
        # Extract vulnerabilities
        vulns = data.get('vulnerabilities') or data.get('vulns')
        if vulns and isinstance(vulns, list):
            result.vulnerabilities = vulns
        
        # Extract breach data
        breaches = data.get('breaches') or data.get('breach_data')
        if breaches and isinstance(breaches, list):
            result.breach_data = breaches
        
        # Extract reputation scores
        reputation = data.get('reputation') or data.get('reputation_scores')
        if reputation and isinstance(reputation, dict):
            result.reputation_scores = reputation
        
        # Extract scan duration
        duration = data.get('duration') or data.get('scan_duration')
        if duration:
            result.scan_duration = float(duration)
        
        # Extract correlated data
        correlated = data.get('correlated_data') or data.get('correlations')
        if correlated and isinstance(correlated, dict):
            result.correlated_data = correlated
        
        # Extract warnings
        warnings = data.get('warnings') or data.get('errors')
        if warnings:
            if isinstance(warnings, list):
                result.warnings = warnings
            elif isinstance(warnings, str):
                result.warnings = [warnings]
    
    def _extract_from_correlated_data(self, result: SpiderFootResult):
        """Extract specific data types from correlated_data."""
        # Extract domains from correlated data
        for key, values in result.correlated_data.items():
            if 'domain' in key.lower():
                for value in values:
                    domain_match = re.search(r'([a-zA-Z0-9][\w-]*\.[a-zA-Z]{2,})', str(value))
                    if domain_match:
                        domain = domain_match.group(1).lower()
                        if domain not in result.domain_names:
                            result.domain_names.append(domain)
            
            elif 'ip' in key.lower() or 'address' in key.lower():
                for value in values:
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', str(value))
                    if ip_match:
                        ip = ip_match.group(1)
                        if ip not in result.ip_addresses:
                            result.ip_addresses.append(ip)
            
            elif 'email' in key.lower():
                for value in values:
                    email_match = re.search(r'([\w\.-]+@[\w\.-]+\.\w+)', str(value))
                    if email_match:
                        email = email_match.group(1).lower()
                        if email not in result.email_addresses:
                            result.email_addresses.append(email)
