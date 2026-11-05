"""
HAZARUS Advanced Subdomain Discovery Tools
Integration with Subfinder, MassDNS, Sublist3r, and other tools.
"""

import asyncio
import logging
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, UTC
from pathlib import Path


@dataclass
class SubdomainSource:
    """Subdomain source information."""
    source: str
    subdomains: List[str] = field(default_factory=list)
    duration: float = 0.0
    success: bool = True
    error: Optional[str] = None


@dataclass
class AdvancedSubdomainResult:
    """Advanced subdomain discovery result."""
    domain: str
    subdomains: List[str] = field(default_factory=list)
    sources: List[SubdomainSource] = field(default_factory=list)
    total_found: int = 0
    discovered_at: datetime = None

    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.now(UTC)


class AdvancedSubdomainTools:
    """Advanced subdomain discovery with multiple tools."""

    def __init__(self, wordlist_path: Optional[str] = None):
        """
        Initialize advanced subdomain tools.

        Args:
            wordlist_path: Path to custom wordlist for brute force
        """
        self.logger = logging.getLogger("hazarus.advanced_subdomains")
        self.wordlist_path = wordlist_path

        # Default wordlist if none provided
        self.default_wordlist = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
            "app", "blog", "shop", "store", "portal", "dashboard", "panel",
            "secure", "vpn", "cdn", "static", "assets", "img", "images",
            "media", "video", "audio", "docs", "docs", "help", "support",
            "forum", "community", "wiki", "kb", "knowledgebase", "status",
            "monitor", "logs", "metrics", "analytics", "tracking", "pixel",
            "m", "mobile", "touch", "wap", "x", "beta", "alpha", "demo",
            "sandbox", "lab", "experiment", "prod", "production", "live",
            "real", "origin", "direct", "internal", "private", "public",
            "external", "partner", "vendor", "client", "customer", "user",
            "account", "login", "auth", "oauth", "sso", "identity", "idp",
            "dns", "ns1", "ns2", "mx", "smtp", "pop", "imap", "webmail",
            "email", "exchange", "calendar", "contacts", "drive", "files",
            "cloud", "storage", "backup", "archive", "repo", "git", "svn",
            "jenkins", "ci", "cd", "build", "deploy", "release", "artifact",
            "nexus", "artifactory", "registry", "docker", "k8s", "kubernetes",
            "swarm", "nomad", "consul", "vault", "etcd", "zookeeper",
            "kafka", "rabbitmq", "redis", "memcached", "elasticsearch", "mongo",
            "postgres", "mysql", "mariadb", "cassandra", "dynamodb", "s3",
            "blob", "queue", "worker", "job", "scheduler", "cron", "task"
        ]

    async def subfinder_scan(self, domain: str) -> SubdomainSource:
        """
        Run Subfinder for subdomain discovery.

        Args:
            domain: Target domain

        Returns:
            SubdomainSource with results
        """
        source = SubdomainSource(source="subfinder")
        start_time = asyncio.get_event_loop().time()

        try:
            # Check if subfinder is available
            proc = await asyncio.create_subprocess_exec(
                "which", "subfinder",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()

            if proc.returncode != 0:
                source.success = False
                source.error = "subfinder not installed"
                self.logger.warning("subfinder not available")
                return source

            # Run subfinder
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-d", domain, "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=300
            )

            if proc.returncode == 0:
                subdomains = stdout.decode().strip().split("\n")
                source.subdomains = [s for s in subdomains if s and s.strip()]
                source.success = True
                self.logger.info(f"Subfinder found {len(source.subdomains)} subdomains")
            else:
                source.success = False
                source.error = stderr.decode()
                self.logger.warning(f"Subfinder failed: {source.error}")

        except asyncio.TimeoutError:
            source.success = False
            source.error = "timeout"
            self.logger.warning("Subfinder timed out")
        except Exception as e:
            source.success = False
            source.error = str(e)
            self.logger.error(f"Subfinder error: {e}")

        source.duration = asyncio.get_event_loop().time() - start_time
        return source

    async def massdns_bruteforce(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None
    ) -> SubdomainSource:
        """
        Run MassDNS for high-speed DNS brute force.

        Args:
            domain: Target domain
            wordlist: Custom wordlist (uses default if None)

        Returns:
            SubdomainSource with results
        """
        source = SubdomainSource(source="massdns")
        start_time = asyncio.get_event_loop().time()

        try:
            # Check if massdns is available
            proc = await asyncio.create_subprocess_exec(
                "which", "massdns",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()

            if proc.returncode != 0:
                source.success = False
                source.error = "massdns not installed"
                self.logger.warning("massdns not available")
                return source

            # Use provided wordlist or default
            if wordlist is None:
                wordlist = self.default_wordlist

            # Create temporary wordlist file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                for subdomain in wordlist:
                    f.write(f"{subdomain}.{domain}\n")
                wordlist_path = f.name

            try:
                # Run massdns
                proc = await asyncio.create_subprocess_exec(
                    "massdns",
                    "-r", "/etc/resolv.conf",  # Use system resolvers
                    "-t", "A",  # Only A records
                    "-o", "S",  # Simple output
                    wordlist_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=600
                )

                if proc.returncode == 0:
                    # Parse output: subdomain.domain.com. A 1.2.3.4
                    lines = stdout.decode().strip().split("\n")
                    subdomains = set()
                    for line in lines:
                        if line and " A " in line:
                            parts = line.split()
                            if parts:
                                subdomain = parts[0].rstrip('.')
                                subdomains.add(subdomain)

                    source.subdomains = list(subdomains)
                    source.success = True
                    self.logger.info(f"MassDNS found {len(source.subdomains)} subdomains")
                else:
                    source.success = False
                    source.error = stderr.decode()
                    self.logger.warning(f"MassDNS failed: {source.error}")

            finally:
                # Clean up temp file
                Path(wordlist_path).unlink(missing_ok=True)

        except asyncio.TimeoutError:
            source.success = False
            source.error = "timeout"
            self.logger.warning("MassDNS timed out")
        except Exception as e:
            source.success = False
            source.error = str(e)
            self.logger.error(f"MassDNS error: {e}")

        source.duration = asyncio.get_event_loop().time() - start_time
        return source

    async def sublist3r_scan(self, domain: str) -> SubdomainSource:
        """
        Run Sublist3r for subdomain discovery.

        Args:
            domain: Target domain

        Returns:
            SubdomainSource with results
        """
        source = SubdomainSource(source="sublist3r")
        start_time = asyncio.get_event_loop().time()

        try:
            # Check if sublist3r is available
            proc = await asyncio.create_subprocess_exec(
                "which", "sublist3r",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()

            if proc.returncode != 0:
                source.success = False
                source.error = "sublist3r not installed"
                self.logger.warning("sublist3r not available")
                return source

            # Run sublist3r
            proc = await asyncio.create_subprocess_exec(
                "sublist3r", "-d", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=300
            )

            if proc.returncode == 0:
                subdomains = stdout.decode().strip().split("\n")
                source.subdomains = [s for s in subdomains if s and s.strip()]
                source.success = True
                self.logger.info(f"Sublist3r found {len(source.subdomains)} subdomains")
            else:
                source.success = False
                source.error = stderr.decode()
                self.logger.warning(f"Sublist3r failed: {source.error}")

        except asyncio.TimeoutError:
            source.success = False
            source.error = "timeout"
            self.logger.warning("Sublist3r timed out")
        except Exception as e:
            source.success = False
            source.error = str(e)
            self.logger.error(f"Sublist3r error: {e}")

        source.duration = asyncio.get_event_loop().time() - start_time
        return source

    async def assetfinder_scan(self, domain: str) -> SubdomainSource:
        """
        Run Assetfinder for subdomain discovery.

        Args:
            domain: Target domain

        Returns:
            SubdomainSource with results
        """
        source = SubdomainSource(source="assetfinder")
        start_time = asyncio.get_event_loop().time()

        try:
            # Check if assetfinder is available
            proc = await asyncio.create_subprocess_exec(
                "which", "assetfinder",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()

            if proc.returncode != 0:
                source.success = False
                source.error = "assetfinder not installed"
                self.logger.warning("assetfinder not available")
                return source

            # Run assetfinder
            proc = await asyncio.create_subprocess_exec(
                "assetfinder", "--subs-only", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=300
            )

            if proc.returncode == 0:
                subdomains = stdout.decode().strip().split("\n")
                source.subdomains = [s for s in subdomains if s and s.strip()]
                source.success = True
                self.logger.info(f"Assetfinder found {len(source.subdomains)} subdomains")
            else:
                source.success = False
                source.error = stderr.decode()
                self.logger.warning(f"Assetfinder failed: {source.error}")

        except asyncio.TimeoutError:
            source.success = False
            source.error = "timeout"
            self.logger.warning("Assetfinder timed out")
        except Exception as e:
            source.success = False
            source.error = str(e)
            self.logger.error(f"Assetfinder error: {e}")

        source.duration = asyncio.get_event_loop().time() - start_time
        return source

    async def discover_all(
        self,
        domain: str,
        tools: Optional[List[str]] = None
    ) -> AdvancedSubdomainResult:
        """
        Run all available subdomain discovery tools.

        Args:
            domain: Target domain
            tools: List of tools to run (default: all available)

        Returns:
            AdvancedSubdomainResult with aggregated results
        """
        if tools is None:
            tools = ["subfinder", "massdns", "sublist3r", "assetfinder"]

        result = AdvancedSubdomainResult(domain=domain)
        self.logger.info(f"Starting advanced subdomain discovery for {domain}")

        # Run each tool
        tasks = []
        for tool in tools:
            if tool == "subfinder":
                tasks.append(self.subfinder_scan(domain))
            elif tool == "massdns":
                tasks.append(self.massdns_bruteforce(domain))
            elif tool == "sublist3r":
                tasks.append(self.sublist3r_scan(domain))
            elif tool == "assetfinder":
                tasks.append(self.assetfinder_scan(domain))

        # Run tasks in parallel
        sources = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        all_subdomains = set()
        for source in sources:
            if isinstance(source, Exception):
                self.logger.error(f"Tool error: {source}")
                continue

            result.sources.append(source)
            if source.success:
                all_subdomains.update(source.subdomains)

        result.subdomains = list(all_subdomains)
        result.total_found = len(result.subdomains)

        self.logger.info(
            f"Advanced subdomain discovery complete: "
            f"{result.total_found} subdomains from {len(result.sources)} sources"
        )

        return result
