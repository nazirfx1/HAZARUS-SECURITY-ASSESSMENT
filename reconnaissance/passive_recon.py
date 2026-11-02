"""
HAZARUS Passive Reconnaissance
Passive information gathering.
"""

import asyncio
import logging
import httpx
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse
import re


@dataclass
class PassiveReconResult:
    """Passive reconnaissance result."""
    target: str
    technologies: List[str] = None
    cloud_providers: List[str] = None
    social_media: List[str] = None
    email_addresses: List[str] = None
    phone_numbers: List[str] = None
    repositories: List[str] = None
    cloud_storage: List[str] = None
    meta_tags: Dict[str, str] = None

    def __post_init__(self):
        if self.technologies is None:
            self.technologies = []
        if self.cloud_providers is None:
            self.cloud_providers = []
        if self.social_media is None:
            self.social_media = []
        if self.email_addresses is None:
            self.email_addresses = []
        if self.phone_numbers is None:
            self.phone_numbers = []
        if self.repositories is None:
            self.repositories = []
        if self.cloud_storage is None:
            self.cloud_storage = []
        if self.meta_tags is None:
            self.meta_tags = {}


class PassiveRecon:
    """Passive reconnaissance module."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.logger = logging.getLogger("hazarus.passive_recon")

    async def gather(self, target: str) -> PassiveReconResult:
        """Gather passive information about a target."""
        self.logger.info(f"Gathering passive info for {target}")

        result = PassiveReconResult(target=target)

        # Determine if target is domain or URL
        if target.startswith(("http://", "https://")):
            base_url = target
            domain = urlparse(target).netloc
        else:
            base_url = f"https://{target}"
            domain = target

        # Fetch the main page
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(base_url)
                content = response.text
                headers = dict(response.headers)

                # Extract meta tags
                result.meta_tags = self._extract_meta_tags(content)

                # Identify technologies
                result.technologies = self._identify_technologies(content, headers)

                # Identify cloud providers
                result.cloud_providers = self._identify_cloud_providers(headers, content)

                # Extract email addresses
                result.email_addresses = self._extract_emails(content)

                # Extract phone numbers
                result.phone_numbers = self._extract_phones(content)

                # Look for social media links
                result.social_media = self._extract_social_media(content)

                # Look for repository links
                result.repositories = self._extract_repositories(content)

                # Look for cloud storage links
                result.cloud_storage = self._extract_cloud_storage(content)

        except Exception as e:
            self.logger.error(f"Failed to gather passive info: {e}")

        return result

    def _extract_meta_tags(self, html: str) -> Dict[str, str]:
        """Extract meta tags from HTML."""
        meta_tags = {}

        # Common meta patterns
        patterns = {
            'description': r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
            'keywords': r'<meta[^>]+name=["\']keywords["\'][^>]+content=["\']([^"\']+)["\']',
            'author': r'<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']+)["\']',
            'generator': r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        }

        for name, pattern in patterns.items():
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                meta_tags[name] = match.group(1)

        return meta_tags

    def _identify_technologies(self, html: str, headers: Dict[str, str]) -> List[str]:
        """Identify technologies from HTML and headers."""
        technologies = []

        # Check headers
        server = headers.get("server", "").lower()
        if "nginx" in server:
            technologies.append("Nginx")
        if "apache" in server:
            technologies.append("Apache")
        if "iis" in server:
            technologies.append("IIS")

        x_powered_by = headers.get("x-powered-by", "").lower()
        if "php" in x_powered_by:
            technologies.append("PHP")
        if "asp.net" in x_powered_by:
            technologies.append("ASP.NET")
        if "express" in x_powered_by:
            technologies.append("Express")

        # Check HTML content
        if "jquery" in html.lower():
            technologies.append("jQuery")
        if "react" in html.lower():
            technologies.append("React")
        if "vue" in html.lower():
            technologies.append("Vue.js")
        if "angular" in html.lower():
            technologies.append("Angular")
        if "bootstrap" in html.lower():
            technologies.append("Bootstrap")
        if "wordpress" in html.lower():
            technologies.append("WordPress")
        if "drupal" in html.lower():
            technologies.append("Drupal")
        if "joomla" in html.lower():
            technologies.append("Joomla")

        return list(set(technologies))

    def _identify_cloud_providers(self, headers: Dict[str, str], html: str) -> List[str]:
        """Identify cloud providers."""
        providers = []

        # Check headers
        x_amz_id = headers.get("x-amz-id", "")
        if x_amz_id:
            providers.append("AWS")

        x_google_backend = headers.get("x-google-backend", "")
        if x_google_backend:
            providers.append("Google Cloud")

        x_azure_ref = headers.get("x-azure-ref", "")
        if x_azure_ref:
            providers.append("Azure")

        # Check CDN headers
        cf_ray = headers.get("cf-ray", "")
        if cf_ray:
            providers.append("Cloudflare")

        # Check HTML for cloud references
        html_lower = html.lower()
        if "amazonaws.com" in html_lower:
            providers.append("AWS")
        if "googleusercontent.com" in html_lower:
            providers.append("Google Cloud")
        if "azurewebsites.net" in html_lower:
            providers.append("Azure")
        if "cloudflare" in html_lower:
            providers.append("Cloudflare")

        return list(set(providers))

    def _extract_emails(self, html: str) -> List[str]:
        """Extract email addresses from HTML."""
        pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(pattern, html)
        return list(set(emails))

    def _extract_phones(self, html: str) -> List[str]:
        """Extract phone numbers from HTML."""
        # Simple pattern for phone numbers
        patterns = [
            r'\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
            r'\+?[0-9]{1,3}[-.\s]?[0-9]{3}[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'
        ]

        phones = []
        for pattern in patterns:
            phones.extend(re.findall(pattern, html))

        return list(set(phones))

    def _extract_social_media(self, html: str) -> List[str]:
        """Extract social media links."""
        social_patterns = {
            'twitter': r'https?://(?:www\.)?twitter\.com/\w+',
            'facebook': r'https?://(?:www\.)?facebook\.com/\w+',
            'linkedin': r'https?://(?:www\.)?linkedin\.com/\w+',
            'instagram': r'https?://(?:www\.)?instagram\.com/\w+',
            'youtube': r'https?://(?:www\.)?youtube\.com/\w+',
        }

        social_links = []
        for platform, pattern in social_patterns.items():
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                social_links.extend(matches)

        return list(set(social_links))

    def _extract_repositories(self, html: str) -> List[str]:
        """Extract repository links."""
        repo_patterns = [
            r'https?://(?:www\.)?github\.com/[\w-]+/[\w-]+',
            r'https?://(?:www\.)?gitlab\.com/[\w-]+/[\w-]+',
            r'https?://(?:www\.)?bitbucket\.org/[\w-]+/[\w-]+',
        ]

        repos = []
        for pattern in repo_patterns:
            repos.extend(re.findall(pattern, html, re.IGNORECASE))

        return list(set(repos))

    def _extract_cloud_storage(self, html: str) -> List[str]:
        """Extract cloud storage links."""
        storage_patterns = [
            r'https?://[\w-]+\.s3\.amazonaws\.com/[\w/-]+',
            r'https?://[\w-]+\.storage\.googleapis\.com/[\w/-]+',
            r'https?://[\w-]+\.blob\.core\.windows\.net/[\w/-]+',
        ]

        storage = []
        for pattern in storage_patterns:
            storage.extend(re.findall(pattern, html, re.IGNORECASE))

        return list(set(storage))

    def to_dict(self, result: PassiveReconResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": result.target,
            "technologies": result.technologies,
            "cloud_providers": result.cloud_providers,
            "social_media": result.social_media,
            "email_addresses": result.email_addresses,
            "phone_numbers": result.phone_numbers,
            "repositories": result.repositories,
            "cloud_storage": result.cloud_storage,
            "meta_tags": result.meta_tags
        }
