"""
HAZARUS Enhanced Passive Reconnaissance
Wappalyzer, GitHub scanning, DNSDumpster, and advanced passive gathering.
"""

import asyncio
import logging
import httpx
import re
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, UTC


@dataclass
class Technology:
    """Technology detection result."""
    name: str
    category: str
    version: Optional[str] = None
    confidence: str = "medium"


@dataclass
class GitHubRepo:
    """GitHub repository information."""
    name: str
    url: str
    description: Optional[str] = None
    stars: int = 0
    forks: int = 0
    language: Optional[str] = None
    last_updated: Optional[str] = None


@dataclass
class EnhancedPassiveResult:
    """Enhanced passive reconnaissance result."""
    target: str
    technologies: List[Technology] = field(default_factory=list)
    github_repos: List[GitHubRepo] = field(default_factory=list)
    dnsdumpster_data: Dict[str, Any] = field(default_factory=dict)
    social_media: Dict[str, str] = field(default_factory=dict)
    discovered_at: datetime = None

    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.now(UTC)


class EnhancedPassiveRecon:
    """Enhanced passive reconnaissance capabilities."""

    def __init__(self):
        self.logger = logging.getLogger("hazarus.enhanced_passive")

        # Technology detection patterns (simplified Wappalyzer-like)
        self.tech_patterns = {
            "wordpress": {
                "category": "CMS",
                "patterns": [r"wp-content", r"wp-includes", r"wordpress"]
            },
            "drupal": {
                "category": "CMS",
                "patterns": [r"/sites/default/files", r"drupal"]
            },
            "joomla": {
                "category": "CMS",
                "patterns": [r"/components/", r"joomla"]
            },
            "react": {
                "category": "JavaScript Framework",
                "patterns": [r"react", r"react-dom"]
            },
            "vue": {
                "category": "JavaScript Framework",
                "patterns": [r"vue", r"vue-router"]
            },
            "angular": {
                "category": "JavaScript Framework",
                "patterns": [r"angular", r"ng-app"]
            },
            "jquery": {
                "category": "JavaScript Library",
                "patterns": [r"jquery", r"\.jquery"]
            },
            "bootstrap": {
                "category": "CSS Framework",
                "patterns": [r"bootstrap", r"bootstrap-"]
            },
            "tailwind": {
                "category": "CSS Framework",
                "patterns": [r"tailwind", r"tw-"]
            },
            "nginx": {
                "category": "Server",
                "patterns": [r"nginx", r"server: nginx"]
            },
            "apache": {
                "category": "Server",
                "patterns": [r"apache", r"server: apache"]
            },
            "cloudflare": {
                "category": "CDN",
                "patterns": [r"cloudflare", r"cf-ray"]
            },
            "aws": {
                "category": "Cloud",
                "patterns": [r"amazonaws", r"s3\.amazonaws"]
            },
            "gcp": {
                "category": "Cloud",
                "patterns": [r"googleusercontent", r"cloud\.google"]
            },
            "azure": {
                "category": "Cloud",
                "patterns": [r"azurewebsites", r"windows\.net"]
            }
        }

    async def wappalyzer_detect(self, url: str) -> List[Technology]:
        """
        Detect technologies using Wappalyzer-like patterns.

        Args:
            url: Target URL

        Returns:
            List of Technology objects
        """
        technologies = []

        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(url)

                # Check headers
                headers_text = str(response.headers).lower()
                body_text = response.text.lower()

                # Check each technology pattern
                for tech_name, tech_info in self.tech_patterns.items():
                    for pattern in tech_info["patterns"]:
                        if re.search(pattern, headers_text) or re.search(pattern, body_text):
                            technologies.append(Technology(
                                name=tech_name,
                                category=tech_info["category"],
                                confidence="medium"
                            ))
                            break

                self.logger.info(f"Wappalyzer: {len(technologies)} technologies detected")

        except Exception as e:
            self.logger.error(f"Wappalyzer error: {e}")

        return technologies

    async def github_scan(self, organization: str) -> List[GitHubRepo]:
        """
        Scan GitHub organization for repositories.

        Args:
            organization: GitHub organization name

        Returns:
            List of GitHubRepo objects
        """
        repos = []

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Query GitHub API (public, no auth required)
                response = await client.get(
                    f"https://api.github.com/orgs/{organization}/repos",
                    headers={"Accept": "application/vnd.github.v3+json"}
                )

                if response.status_code == 200:
                    data = response.json()
                    for repo_data in data:
                        repos.append(GitHubRepo(
                            name=repo_data.get("name"),
                            url=repo_data.get("html_url"),
                            description=repo_data.get("description"),
                            stars=repo_data.get("stargazers_count", 0),
                            forks=repo_data.get("forks_count", 0),
                            language=repo_data.get("language"),
                            last_updated=repo_data.get("updated_at")
                        ))

                    self.logger.info(f"GitHub: {len(repos)} repositories found")
                else:
                    self.logger.warning(f"GitHub API returned {response.status_code}")

        except Exception as e:
            self.logger.error(f"GitHub scan error: {e}")

        return repos

    async def dnsdumpster_query(self, domain: str) -> Dict[str, Any]:
        """
        Query DNSDumpster for DNS reconnaissance.

        Args:
            domain: Target domain

        Returns:
            Dictionary with DNSDumpster data
        """
        result = {}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # DNSDumpster requires a session cookie
                session = client
                await session.get("https://dnsdumpster.com/")

                # Submit domain
                response = await session.post(
                    "https://dnsdumpster.com/",
                    data={"target": domain, "serverselection": "Regular"}
                )

                if response.status_code == 200:
                    # Parse results (DNSDumpster returns HTML with maps)
                    # This is a simplified version - full parsing would require HTML parsing
                    result["status"] = "queried"
                    result["domain"] = domain
                    self.logger.info(f"DNSDumpster: queried {domain}")
                else:
                    self.logger.warning(f"DNSDumpster returned {response.status_code}")

        except Exception as e:
            self.logger.error(f"DNSDumpster error: {e}")

        return result

    async def social_media_enumerate(self, target: str) -> Dict[str, str]:
        """
        Enumerate social media accounts for target.

        Args:
            target: Target (username or organization)

        Returns:
            Dictionary of platform -> account URL
        """
        accounts = {}

        # Common social media platforms
        platforms = {
            "twitter": f"https://twitter.com/{target}",
            "github": f"https://github.com/{target}",
            "linkedin": f"https://linkedin.com/company/{target}",
            "facebook": f"https://facebook.com/{target}",
            "instagram": f"https://instagram.com/{target}",
            "youtube": f"https://youtube.com/@{target}",
            "medium": f"https://medium.com/@{target}"
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            for platform, url in platforms.items():
                try:
                    response = await client.head(url, follow_redirects=False)
                    if response.status_code in [200, 301, 302]:
                        accounts[platform] = url
                        self.logger.debug(f"Found {platform} account")
                except:
                    pass

        self.logger.info(f"Social media: {len(accounts)} accounts found")
        return accounts

    async def scan_all(
        self,
        target: str,
        target_type: str = "domain"
    ) -> EnhancedPassiveResult:
        """
        Run all enhanced passive reconnaissance.

        Args:
            target: Target (domain, organization, or username)
            target_type: Type of target (domain, organization, username)

        Returns:
            EnhancedPassiveResult with all findings
        """
        result = EnhancedPassiveResult(target=target)
        self.logger.info(f"Starting enhanced passive recon for {target}")

        # Run based on target type
        if target_type == "domain":
            # Wappalyzer technology detection
            try:
                url = f"https://{target}"
                result.technologies = await self.wappalyzer_detect(url)
            except:
                pass

            # DNSDumpster
            try:
                result.dnsdumpster_data = await self.dnsdumpster_query(target)
            except:
                pass

        elif target_type == "organization":
            # GitHub scan
            try:
                result.github_repos = await self.github_scan(target)
            except:
                pass

            # Social media
            try:
                result.social_media = await self.social_media_enumerate(target)
            except:
                pass

        elif target_type == "username":
            # Social media only
            try:
                result.social_media = await self.social_media_enumerate(target)
            except:
                pass

        self.logger.info("Enhanced passive reconnaissance complete")
        return result
