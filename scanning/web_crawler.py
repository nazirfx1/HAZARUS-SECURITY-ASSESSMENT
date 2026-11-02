"""
HAZARUS Web Crawler
Web application crawling and discovery.
"""

import asyncio
import logging
import httpx
from typing import Dict, Any, List, Set, Optional
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re


@dataclass
class Page:
    """A crawled page."""
    url: str
    status_code: int
    title: Optional[str] = None
    content_type: Optional[str] = None
    links: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class CrawlResult:
    """Web crawl result."""
    target: str
    pages: List[Page] = field(default_factory=list)
    discovered_urls: Set[str] = field(default_factory=set)
    endpoints: List[str] = field(default_factory=list)
    parameters: Set[str] = field(default_factory=set)
    technologies: List[str] = field(default_factory=list)
    crawled_at: datetime = None

    def __post_init__(self):
        if self.crawled_at is None:
            self.crawled_at = datetime.utcnow()


class WebCrawler:
    """Web crawler module."""

    def __init__(self, timeout: int = 10, max_pages: int = 100):
        self.timeout = timeout
        self.max_pages = max_pages
        self.logger = logging.getLogger("hazarus.web_crawler")

        self.visited: Set[str] = set()
        self.to_visit: List[str] = []
        self.user_agent = "HAZARUS/2.0 (Security Assessment Framework)"

    async def crawl(self, target: str, max_depth: int = 3) -> CrawlResult:
        """Crawl web application."""
        self.logger.info(f"Crawling {target} with max depth {max_depth}")

        result = CrawlResult(target=target)

        # Ensure target has protocol
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        self.to_visit = [target]
        self.visited = set()

        while self.to_visit and len(result.pages) < self.max_pages:
            url = self.to_visit.pop(0)

            if url in self.visited:
                continue

            page = await self._crawl_page(url)
            if page:
                result.pages.append(page)
                result.discovered_urls.add(url)

                # Extract links
                for link in page.links:
                    if self._should_crawl(link, target) and link not in self.visited:
                        self.to_visit.append(link)

                # Extract endpoints
                result.endpoints.extend(self._extract_endpoints(page))

                # Extract parameters
                result.parameters.update(self._extract_parameters(page))

                # Identify technologies
                result.technologies.extend(self._identify_technologies(page))

            self.visited.add(url)

        result.endpoints = list(set(result.endpoints))
        result.technologies = list(set(result.technologies))

        self.logger.info(f"Crawl complete: {len(result.pages)} pages crawled")
        return result

    async def _crawl_page(self, url: str) -> Optional[Page]:
        """Crawl a single page."""
        try:
            headers = {"User-Agent": self.user_agent}

            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(url, headers=headers)

                page = Page(
                    url=url,
                    status_code=response.status_code,
                    content_type=response.headers.get("content-type"),
                    headers=dict(response.headers)
                )

                # Parse HTML
                if "text/html" in page.content_type:
                    soup = BeautifulSoup(response.text, "html.parser")

                    # Get title
                    title_tag = soup.find("title")
                    page.title = title_tag.text.strip() if title_tag else None

                    # Extract links
                    page.links = self._extract_links(soup, url)

                    # Extract forms
                    page.forms = self._extract_forms(soup, url)

                    # Extract scripts
                    page.scripts = self._extract_scripts(soup, url)

                    # Extract comments
                    page.comments = self._extract_comments(soup)

                return page

        except Exception as e:
            self.logger.error(f"Failed to crawl {url}: {e}")
            return None

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract links from page."""
        links = []

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            absolute_url = urljoin(base_url, href)
            links.append(absolute_url)

        return links

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from page."""
        forms = []

        for form in soup.find_all("form"):
            form_info = {
                "action": urljoin(base_url, form.get("action", "")),
                "method": form.get("method", "GET").upper(),
                "fields": []
            }

            for input_tag in form.find_all("input"):
                field_info = {
                    "name": input_tag.get("name"),
                    "type": input_tag.get("type", "text"),
                    "value": input_tag.get("value")
                }
                form_info["fields"].append(field_info)

            forms.append(form_info)

        return forms

    def _extract_scripts(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract script sources."""
        scripts = []

        for script in soup.find_all("script", src=True):
            src = urljoin(base_url, script["src"])
            scripts.append(src)

        return scripts

    def _extract_comments(self, soup: BeautifulSoup) -> List[str]:
        """Extract HTML comments."""
        comments = []

        for comment in soup.find_all(string=lambda text: isinstance(text, type(soup)) and text.strip().startswith("<!--")):
            comment_text = comment.strip()
            if len(comment_text) > 5:  # Filter short comments
                comments.append(comment_text)

        return comments

    def _should_crawl(self, url: str, base_url: str) -> bool:
        """Determine if URL should be crawled."""
        parsed = urlparse(url)
        base_parsed = urlparse(base_url)

        # Same domain
        if parsed.netloc != base_parsed.netloc:
            return False

        # Skip common non-content paths
        skip_paths = [".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".ttf"]
        if any(url.lower().endswith(ext) for ext in skip_paths):
            return False

        return True

    def _extract_endpoints(self, page: Page) -> List[str]:
        """Extract API endpoints from page."""
        endpoints = []

        # From forms
        for form in page.forms:
            endpoints.append(f"{form['method']} {form['action']}")

        # From links that look like API endpoints
        for link in page.links:
            if "/api/" in link or link.endswith(".json"):
                endpoints.append(f"GET {link}")

        return endpoints

    def _extract_parameters(self, page: Page) -> Set[str]:
        """Extract parameter names."""
        params = set()

        # From URL query parameters
        for link in page.links:
            parsed = urlparse(link)
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        params.add(param.split("=")[0])

        # From form fields
        for form in page.forms:
            for field in form["fields"]:
                if field["name"]:
                    params.add(field["name"])

        return params

    def _identify_technologies(self, page: Page) -> List[str]:
        """Identify technologies from page."""
        technologies = []

        # From scripts
        for script in page.scripts:
            if "jquery" in script.lower():
                technologies.append("jQuery")
            if "react" in script.lower():
                technologies.append("React")
            if "vue" in script.lower():
                technologies.append("Vue.js")
            if "angular" in script.lower():
                technologies.append("Angular")
            if "bootstrap" in script.lower():
                technologies.append("Bootstrap")

        # From headers
        server = page.headers.get("server", "").lower()
        if "nginx" in server:
            technologies.append("Nginx")
        if "apache" in server:
            technologies.append("Apache")

        powered_by = page.headers.get("x-powered-by", "").lower()
        if "php" in powered_by:
            technologies.append("PHP")
        if "asp.net" in powered_by:
            technologies.append("ASP.NET")

        return technologies

    def to_dict(self, result: CrawlResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": result.target,
            "pages_crawled": len(result.pages),
            "discovered_urls": list(result.discovered_urls),
            "endpoints": result.endpoints,
            "parameters": list(result.parameters),
            "technologies": result.technologies,
            "crawled_at": result.crawled_at.isoformat()
        }
