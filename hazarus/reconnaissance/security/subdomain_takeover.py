"""
HAZARUS Subdomain Takeover Detection
Detect vulnerable subdomains that can be taken over.
"""

import asyncio
import logging
import httpx
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, UTC


@dataclass
class TakeoverFinding:
    """Subdomain takeover finding."""
    subdomain: str
    vulnerable: bool
    service: Optional[str] = None
    confidence: str = "medium"  # high, medium, low
    evidence: str = ""
    checked_at: datetime = None

    def __post_init__(self):
        if self.checked_at is None:
            self.checked_at = datetime.now(UTC)


@dataclass
class TakeoverResult:
    """Subdomain takeover scan result."""
    domain: str
    findings: List[TakeoverFinding] = field(default_factory=list)
    vulnerable_count: int = 0
    safe_count: int = 0
    scanned_at: datetime = None

    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.now(UTC)


class SubdomainTakeoverDetector:
    """Detect subdomain takeover vulnerabilities."""

    # Common takeover signatures
    TAKEOVER_SIGNATURES = {
        "aws": [
            "The specified bucket does not exist",
            "NoSuchBucket",
            "AccessDenied"
        ],
        "github": [
            "There isn't a GitHub Pages site here",
            "github.com"
        ],
        "heroku": [
            "no such app",
            "herokuapp.com"
        ],
        "cloudfront": [
            "The request could not be satisfied",
            "CloudFront"
        ],
        "azure": [
            "The requested resource does not exist",
            "azurewebsites.net"
        ],
        "fastly": [
            "Fastly error: unknown domain",
            "Fastly"
        ],
        "shopify": [
            "Sorry, this shop is currently unavailable",
            "myshopify.com"
        ],
        "wordpress": [
            "Do you want to register",
            "wordpress.com"
        ],
        "tumblr": [
            "Whatever you're looking for",
            "tumblr.com"
        ],
        "squarespace": [
            "This site can't be reached",
            "squarespace.com"
        ]
    }

    def __init__(self):
        self.logger = logging.getLogger("hazarus.subdomain_takeover")

    async def check_subdomain(self, subdomain: str) -> TakeoverFinding:
        """
        Check a single subdomain for takeover vulnerability.

        Args:
            subdomain: Subdomain to check

        Returns:
            TakeoverFinding with result
        """
        finding = TakeoverFinding(subdomain=subdomain)

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                # Try HTTP and HTTPS
                for protocol in ["http", "https"]:
                    try:
                        url = f"{protocol}://{subdomain}"
                        response = await client.get(url)

                        # Check response body for takeover signatures
                        body = response.text.lower()

                        for service, signatures in self.TAKEOVER_SIGNATURES.items():
                            for sig in signatures:
                                if sig.lower() in body:
                                    finding.vulnerable = True
                                    finding.service = service
                                    finding.confidence = "high"
                                    finding.evidence = f"Found signature '{sig}' in response from {url}"
                                    self.logger.warning(f"Vulnerable: {subdomain} ({service})")
                                    return finding

                        # Check for DNS pointing to CNAME of service
                        if response.status_code in [404, 410, 502, 503]:
                            finding.confidence = "low"
                            finding.evidence = f"Status {response.status_code} from {url}"

                    except httpx.ConnectError:
                        # Connection refused or timeout - possible takeover
                        finding.confidence = "medium"
                        finding.evidence = f"Connection error to {url}"
                    except Exception:
                        pass

        except Exception as e:
            self.logger.warning(f"Error checking {subdomain}: {e}")
            finding.evidence = str(e)

        return finding

    async def scan_subdomains(
        self,
        subdomains: List[str],
        max_concurrent: int = 20
    ) -> TakeoverResult:
        """
        Scan multiple subdomains for takeover vulnerabilities.

        Args:
            subdomains: List of subdomains to check
            max_concurrent: Maximum concurrent checks

        Returns:
            TakeoverResult with all findings
        """
        result = TakeoverResult(domain=subdomains[0] if subdomains else "unknown")
        self.logger.info(f"Scanning {len(subdomains)} subdomains for takeover vulnerabilities")

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(max_concurrent)

        async def check_with_semaphore(subdomain: str) -> TakeoverFinding:
            async with semaphore:
                return await self.check_subdomain(subdomain)

        # Run checks in parallel
        tasks = [check_with_semaphore(sub) for sub in subdomains]
        findings = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for finding in findings:
            if isinstance(finding, Exception):
                self.logger.error(f"Error: {finding}")
                continue

            result.findings.append(finding)

            if finding.vulnerable:
                result.vulnerable_count += 1
            else:
                result.safe_count += 1

        self.logger.info(
            f"Takeover scan complete: "
            f"{result.vulnerable_count} vulnerable, {result.safe_count} safe"
        )

        return result
