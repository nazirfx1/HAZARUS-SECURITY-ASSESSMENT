"""
HAZARUS Virtual Host Enumeration
Enumerate virtual hosts via HTTP Host header.
"""

import asyncio
import logging
import httpx
from typing import List, Optional, Dict, Set
from dataclasses import dataclass, field
from datetime import datetime, UTC


@dataclass
class VirtualHostFinding:
    """Virtual host finding."""
    hostname: str
    ip: str
    status_code: int
    content_length: int
    server_header: Optional[str] = None
    title: Optional[str] = None
    discovered_at: datetime = None

    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.now(UTC)


@dataclass
class VirtualHostResult:
    """Virtual host enumeration result."""
    target_ip: str
    findings: List[VirtualHostFinding] = field(default_factory=list)
    unique_hosts: Set[str] = field(default_factory=set)
    scanned_at: datetime = None

    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.now(UTC)


class VirtualHostEnumerator:
    """Enumerate virtual hosts via HTTP Host header."""

    def __init__(self):
        self.logger = logging.getLogger("hazarus.virtual_host")

        # Default vhost wordlist
        self.default_wordlist = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
            "app", "blog", "shop", "store", "portal", "dashboard", "panel",
            "secure", "vpn", "cdn", "static", "assets", "img", "images",
            "media", "video", "audio", "docs", "help", "support",
            "forum", "community", "wiki", "kb", "status", "monitor",
            "logs", "metrics", "analytics", "tracking", "beta", "alpha",
            "demo", "sandbox", "lab", "prod", "production", "live",
            "origin", "direct", "internal", "private", "public",
            "external", "partner", "vendor", "client", "customer",
            "account", "login", "auth", "oauth", "sso", "identity",
            "dns", "ns1", "ns2", "mx", "smtp", "pop", "imap",
            "webmail", "email", "exchange", "calendar", "contacts",
            "drive", "files", "cloud", "storage", "backup", "archive",
            "repo", "git", "svn", "jenkins", "ci", "cd", "build",
            "deploy", "release", "artifact", "nexus", "artifactory",
            "registry", "docker", "k8s", "kubernetes", "swarm", "nomad",
            "consul", "vault", "etcd", "zookeeper", "kafka", "rabbitmq",
            "redis", "memcached", "elasticsearch", "mongo", "postgres",
            "mysql", "mariadb", "cassandra", "dynamodb", "s3", "blob",
            "queue", "worker", "job", "scheduler", "cron", "task"
        ]

    async def check_vhost(
        self,
        ip: str,
        hostname: str,
        port: int = 80,
        use_https: bool = False
    ) -> Optional[VirtualHostFinding]:
        """
        Check a single virtual host.

        Args:
            ip: Target IP address
            hostname: Hostname to test
            port: Port number
            use_https: Use HTTPS instead of HTTP

        Returns:
            VirtualHostFinding if successful, None otherwise
        """
        try:
            protocol = "https" if use_https else "http"
            url = f"{protocol}://{ip}:{port}"

            headers = {"Host": hostname}

            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                response = await client.get(url, headers=headers)

                # Extract title from HTML
                title = None
                if "text/html" in response.headers.get("content-type", ""):
                    import re
                    title_match = re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE)
                    if title_match:
                        title = title_match.group(1).strip()

                finding = VirtualHostFinding(
                    hostname=hostname,
                    ip=ip,
                    status_code=response.status_code,
                    content_length=len(response.content),
                    server_header=response.headers.get("server"),
                    title=title
                )

                self.logger.debug(f"VHost: {hostname} -> {response.status_code}")
                return finding

        except Exception as e:
            self.logger.debug(f"VHost check failed for {hostname}: {e}")
            return None

    async def enumerate_vhosts(
        self,
        ip: str,
        domain: str,
        wordlist: Optional[List[str]] = None,
        max_concurrent: int = 20
    ) -> VirtualHostResult:
        """
        Enumerate virtual hosts for an IP.

        Args:
            ip: Target IP address
            domain: Base domain for hostname generation
            wordlist: Custom wordlist (uses default if None)
            max_concurrent: Maximum concurrent checks

        Returns:
            VirtualHostResult with all findings
        """
        result = VirtualHostResult(target_ip=ip)

        if wordlist is None:
            wordlist = self.default_wordlist

        # Generate hostnames
        hostnames = []
        for word in wordlist:
            hostnames.append(f"{word}.{domain}")
            hostnames.append(f"{word}-{domain}")
            hostnames.append(f"{word}.{domain.split('.')[0]}")

        self.logger.info(f"Enumerating {len(hostnames)} virtual hosts for {ip}")

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(max_concurrent)

        async def check_with_semaphore(hostname: str) -> Optional[VirtualHostFinding]:
            async with semaphore:
                # Try HTTP first
                finding = await self.check_vhost(ip, hostname, port=80)
                if finding and finding.status_code not in [404, 502, 503]:
                    return finding

                # Try HTTPS if HTTP failed
                finding = await self.check_vhost(ip, hostname, port=443, use_https=True)
                if finding and finding.status_code not in [404, 502, 503]:
                    return finding

                return None

        # Run checks in parallel
        tasks = [check_with_semaphore(hostname) for hostname in hostnames]
        findings = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for finding in findings:
            if isinstance(finding, Exception):
                self.logger.error(f"Error: {finding}")
                continue

            if finding:
                result.findings.append(finding)
                result.unique_hosts.add(finding.hostname)

        self.logger.info(
            f"Virtual host enumeration complete: "
            f"{len(result.unique_hosts)} unique hosts found"
        )

        return result
