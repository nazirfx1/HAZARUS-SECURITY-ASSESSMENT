"""
HAZARUS Enhanced Live Host Discovery
TCP SYN ping, UDP ping, reverse DNS, OS fingerprinting, and CIDR scanning.
"""

import asyncio
import logging
import subprocess
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, UTC
import ipaddress


@dataclass
class EnhancedLiveHost:
    """Enhanced live host information."""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    response_time: Optional[float] = None
    source: str = ""
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    discovered_at: datetime = None

    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.now(UTC)


@dataclass
class EnhancedLiveHostResult:
    """Enhanced live host discovery result."""
    target: str
    hosts: List[EnhancedLiveHost] = field(default_factory=list)
    total_scanned: int = 0
    scan_duration: float = 0.0
    errors: List[str] = field(default_factory=list)
    scanned_at: datetime = None

    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.now(UTC)


class EnhancedLiveHostDiscovery:
    """Enhanced live host discovery capabilities."""

    def __init__(self, timeout: int = 60):
        """
        Initialize enhanced live host discovery.

        Args:
            timeout: Default timeout for operations
        """
        self.timeout = timeout
        self.logger = logging.getLogger("hazarus.enhanced_live_hosts")

    async def tcp_syn_ping(
        self,
        target: str,
        ports: List[int] = None
    ) -> List[EnhancedLiveHost]:
        """
        TCP SYN ping for networks blocking ICMP.

        Args:
            target: Target IP or CIDR
            ports: Ports to check (default: common ports)

        Returns:
            List of EnhancedLiveHost objects
        """
        if ports is None:
            ports = [22, 80, 443, 21, 23, 25, 53, 110, 143, 3306, 3389, 5432, 8080]

        hosts = []
        self.logger.info(f"TCP SYN ping on {target} for {len(ports)} ports")

        try:
            # Check if target is CIDR
            try:
                network = ipaddress.ip_network(target, strict=False)
                is_cidr = True
                target_list = [str(ip) for ip in network.hosts()]
            except:
                is_cidr = False
                target_list = [target]

            # Use nmap for TCP SYN scan (requires root)
            try:
                proc = await asyncio.create_subprocess_exec(
                    "nmap", "-sS", "-p", ",".join(map(str, ports)),
                    "-T4", "--max-retries", "1",
                    *target_list,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout
                )

                # Parse nmap output
                output = stdout.decode()
                for ip in target_list:
                    if ip in output:
                        host = EnhancedLiveHost(ip=ip, source="tcp_syn")
                        hosts.append(host)

            except Exception as e:
                self.logger.warning(f"Nmap TCP SYN scan failed: {e}")

        except Exception as e:
            self.logger.error(f"TCP SYN ping error: {e}")

        return hosts

    async def udp_ping(
        self,
        target: str,
        ports: List[int] = None
    ) -> List[EnhancedLiveHost]:
        """
        UDP ping for service discovery.

        Args:
            target: Target IP
            ports: UDP ports to check

        Returns:
            List of EnhancedLiveHost objects
        """
        if ports is None:
            ports = [53, 67, 68, 123, 161, 500, 514, 520]

        hosts = []
        self.logger.info(f"UDP ping on {target} for {len(ports)} ports")

        try:
            # Use nmap for UDP scan
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-sU", "-p", ",".join(map(str, ports)),
                "-T4", "--max-retries", "1",
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.timeout
            )

            if proc.returncode == 0:
                host = EnhancedLiveHost(ip=target, source="udp")
                hosts.append(host)

        except Exception as e:
            self.logger.warning(f"UDP ping failed: {e}")

        return hosts

    async def reverse_dns_lookup(self, ips: List[str]) -> Dict[str, str]:
        """
        Reverse DNS lookup for hostnames.

        Args:
            ips: List of IP addresses

        Returns:
            Dictionary of IP -> hostname
        """
        results = {}
        self.logger.info(f"Reverse DNS lookup for {len(ips)} IPs")

        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()

            for ip in ips:
                try:
                    # Reverse IP for PTR lookup
                    reversed_ip = ".".join(reversed(ip.split(".")))
                    ptr_record = f"{reversed_ip}.in-addr.arpa"

                    answer = resolver.resolve(ptr_record, "PTR")
                    if answer:
                        hostname = str(answer[0]).rstrip(".")
                        results[ip] = hostname
                        self.logger.debug(f"{ip} -> {hostname}")

                except:
                    results[ip] = None

        except Exception as e:
            self.logger.error(f"Reverse DNS lookup error: {e}")

        return results

    async def os_fingerprinting(self, ip: str) -> Optional[str]:
        """
        OS fingerprinting via p0f or xprobe2.

        Args:
            ip: Target IP

        Returns:
            OS guess or None
        """
        try:
            # Try p0f
            proc = await asyncio.create_subprocess_exec(
                "p0f", "-q", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=30
            )

            if proc.returncode == 0:
                output = stdout.decode()
                # Parse p0f output for OS
                if "Linux" in output:
                    return "Linux"
                elif "Windows" in output:
                    return "Windows"
                elif "BSD" in output:
                    return "BSD"

        except Exception as e:
            self.logger.debug(f"OS fingerprinting failed: {e}")

        return None

    async def cidr_scan(
        self,
        cidr: str,
        method: str = "arp"
    ) -> List[EnhancedLiveHost]:
        """
        Scan entire CIDR range.

        Args:
            cidr: CIDR range (e.g., 192.168.1.0/24)
            method: Scan method (arp, icmp, tcp)

        Returns:
            List of EnhancedLiveHost objects
        """
        hosts = []
        self.logger.info(f"CIDR scan of {cidr} using {method}")

        try:
            network = ipaddress.ip_network(cidr, strict=False)
            target_list = [str(ip) for ip in network.hosts()]

            if method == "arp":
                # Use arping for each host
                from reconnaissance.live_hosts import LiveHostDiscovery
                live_discovery = LiveHostDiscovery(timeout=self.timeout)

                for ip in target_list[:100]:  # Limit to 100 hosts
                    try:
                        result = await live_discovery.discover_hosts(
                            ip,
                            use_arping=True,
                            use_fping=False,
                            use_ipv6=False
                        )
                        for host in result.hosts:
                            enhanced = EnhancedLiveHost(
                                ip=host.ip,
                                mac=host.mac,
                                response_time=host.response_time,
                                source="arp_cidr"
                            )
                            hosts.append(enhanced)
                    except:
                        pass

            elif method == "icmp":
                # Use fping for CIDR
                proc = await asyncio.create_subprocess_exec(
                    "fping", "-c", "1", cidr,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout
                )

                if proc.returncode == 0:
                    # Parse fping output
                    for line in stdout.decode().split("\n"):
                        if "alive" in line:
                            ip = line.split()[0]
                            hosts.append(EnhancedLiveHost(ip=ip, source="icmp_cidr"))

        except Exception as e:
            self.logger.error(f"CIDR scan error: {e}")

        return hosts

    async def discover_enhanced(
        self,
        target: str,
        methods: List[str] = None
    ) -> EnhancedLiveHostResult:
        """
        Run enhanced live host discovery with multiple methods.

        Args:
            target: Target (IP or CIDR)
            methods: List of methods (tcp_syn, udp, reverse_dns, os_fingerprint, cidr)

        Returns:
            EnhancedLiveHostResult with all findings
        """
        if methods is None:
            methods = ["tcp_syn", "reverse_dns"]

        result = EnhancedLiveHostResult(target=target)
        start_time = asyncio.get_event_loop().time()

        self.logger.info(f"Enhanced live host discovery for {target}")

        # Collect IPs for reverse DNS
        all_ips = []

        # TCP SYN ping
        if "tcp_syn" in methods:
            tcp_hosts = await self.tcp_syn_ping(target)
            result.hosts.extend(tcp_hosts)
            all_ips.extend([h.ip for h in tcp_hosts])

        # UDP ping
        if "udp" in methods:
            udp_hosts = await self.udp_ping(target)
            result.hosts.extend(udp_hosts)
            all_ips.extend([h.ip for h in udp_hosts])

        # CIDR scan
        if "cidr" in methods:
            cidr_hosts = await self.cidr_scan(target)
            result.hosts.extend(cidr_hosts)
            all_ips.extend([h.ip for h in cidr_hosts])

        # Reverse DNS lookup
        if "reverse_dns" in methods and all_ips:
            hostnames = await self.reverse_dns_lookup(all_ips)
            for host in result.hosts:
                if host.ip in hostnames:
                    host.hostname = hostnames[host.ip]

        # OS fingerprinting
        if "os_fingerprint" in methods and all_ips:
            for ip in all_ips[:10]:  # Limit to 10 hosts
                os_guess = await self.os_fingerprinting(ip)
                for host in result.hosts:
                    if host.ip == ip:
                        host.os_guess = os_guess

        result.total_scanned = len(all_ips)
        result.scan_duration = asyncio.get_event_loop().time() - start_time

        self.logger.info(
            f"Enhanced live host discovery complete: "
            f"{len(result.hosts)} hosts found in {result.scan_duration:.2f}s"
        )

        return result
