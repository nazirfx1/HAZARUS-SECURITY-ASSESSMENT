"""
HAZARUS Nmap Scanner
Nmap integration for network scanning.
"""

import asyncio
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import subprocess
import os


@dataclass
class Port:
    """Port information."""
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None
    extra_info: Optional[str] = None


@dataclass
class Host:
    """Host information."""
    ip: str
    hostname: Optional[str] = None
    state: str = "unknown"
    ports: List[Port] = field(default_factory=list)
    os: Optional[str] = None
    uptime: Optional[str] = None


@dataclass
class NmapResult:
    """Nmap scan result."""
    targets: List[str]
    hosts: List[Host] = field(default_factory=list)
    scan_start: Optional[datetime] = None
    scan_end: Optional[datetime] = None
    command: Optional[str] = None
    exit_status: Optional[int] = None


class NmapScanner:
    """Nmap scanning module."""

    def __init__(self):
        self.logger = logging.getLogger("hazarus.nmap_scanner")
        self.is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False

    async def scan(
        self,
        targets: List[str],
        ports: str = "1-65535",
        scan_type: str = None,  # Auto-detect based on root
        service_detection: bool = True,
        os_detection: bool = True,
        aggressive: bool = False,
        timeout: int = 600
    ) -> NmapResult:
        """Scan targets with Nmap (defaults to advanced settings)."""
        self.logger.info(f"Scanning {len(targets)} targets, ports {ports}")

        result = NmapResult(targets=targets, scan_start=datetime.utcnow())

        # Auto-detect scan type based on root privileges
        if scan_type is None:
            if self.is_root:
                scan_type = "sS"  # SYN scan (faster, requires root)
                self.logger.info("Running as root, using SYN scan (-sS)")
            else:
                scan_type = "sT"  # TCP connect scan (no root required)
                self.logger.info("Not running as root, using TCP connect scan (-sT)")

        # Build nmap command
        command = self._build_command(
            targets,
            ports,
            scan_type,
            service_detection,
            os_detection,
            aggressive
        )

        result.command = command
        self.logger.debug(f"Nmap command: {command}")

        try:
            # Execute nmap
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            result.exit_status = process.returncode
            result.scan_end = datetime.utcnow()

            # Parse XML output
            if process.returncode == 0:
                xml_output = stdout.decode()
                result.hosts = self._parse_xml(xml_output)
                self.logger.info(f"Scan complete: {len(result.hosts)} hosts scanned")
            else:
                self.logger.error(f"Nmap failed with status {process.returncode}")
                self.logger.error(f"stderr: {stderr.decode()}")

        except asyncio.TimeoutError:
            self.logger.error("Nmap scan timed out")
            result.exit_status = -1
        except Exception as e:
            self.logger.error(f"Nmap scan failed: {e}")
            result.exit_status = -1

        return result

    def _build_command(
        self,
        targets: List[str],
        ports: str,
        scan_type: str,
        service_detection: bool,
        os_detection: bool,
        aggressive: bool
    ) -> List[str]:
        """Build nmap command."""
        cmd = ["nmap"]

        # Scan type
        if scan_type == "sS":
            cmd.append("-sS")
        else:
            cmd.append("-sT")  # Default to TCP connect (no root required)

        # Port specification
        cmd.append("-p")
        cmd.append(ports)

        # Service detection
        if service_detection:
            cmd.append("-sV")

        # OS detection
        if os_detection:
            cmd.append("-O")

        # Aggressive scan
        if aggressive:
            cmd.append("-A")

        # XML output
        cmd.append("-oX")
        cmd.append("-")  # stdout

        # Add targets
        cmd.extend(targets)

        return cmd

    def _parse_xml(self, xml_data: str) -> List[Host]:
        """Parse Nmap XML output."""
        hosts = []

        try:
            root = ET.fromstring(xml_data)

            for host_elem in root.findall("host"):
                host = self._parse_host(host_elem)
                hosts.append(host)

        except Exception as e:
            self.logger.error(f"Failed to parse Nmap XML: {e}")

        return hosts

    def _parse_host(self, host_elem: ET.Element) -> Host:
        """Parse a host element."""
        # Get IP address
        address_elem = host_elem.find(".//address[@addrtype='ipv4']")
        ip = address_elem.get("addr") if address_elem is not None else "unknown"

        # Get hostname
        hostname_elem = host_elem.find(".//hostname")
        hostname = hostname_elem.get("name") if hostname_elem is not None else None

        # Get state
        status_elem = host_elem.find("status")
        state = status_elem.get("state") if status_elem is not None else "unknown"

        host = Host(ip=ip, hostname=hostname, state=state)

        # Get ports
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port = self._parse_port(port_elem)
                host.ports.append(port)

        # Get OS
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch_elem = os_elem.find("osmatch")
            if osmatch_elem is not None:
                host.os = osmatch_elem.get("name")

        return host

    def _parse_port(self, port_elem: ET.Element) -> Port:
        """Parse a port element."""
        port_id = int(port_elem.get("portid"))
        protocol = port_elem.get("protocol")

        state_elem = port_elem.find("state")
        state = state_elem.get("state") if state_elem is not None else "unknown"

        service_elem = port_elem.find("service")
        service = None
        version = None
        product = None
        extra_info = None

        if service_elem is not None:
            service = service_elem.get("name")
            version = service_elem.get("version")
            product = service_elem.get("product")
            extra_info = service_elem.get("extrainfo")

        return Port(
            port=port_id,
            protocol=protocol,
            state=state,
            service=service,
            version=version,
            product=product,
            extra_info=extra_info
        )

    async def quick_scan(self, target: str) -> List[int]:
        """Quick scan for open ports."""
        self.logger.info(f"Quick scanning {target}")

        # Auto-detect scan type based on root privileges
        if self.is_root:
            scan_type = "-sS"  # SYN scan (requires root)
        else:
            scan_type = "-sT"  # TCP connect scan (no root required)

        command = ["nmap", scan_type, "--open", "-oX", "-", target]

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                result = self._parse_xml(stdout.decode())
                if result:
                    return [p.port for p in result[0].ports if p.state == "open"]

        except Exception as e:
            self.logger.error(f"Quick scan failed: {e}")

        return []

    async def advanced_scan(
        self,
        targets: List[str],
        ports: str = "1-65535",
        tcp_scan: bool = True,
        udp_scan: bool = False,
        service_detection: bool = True,
        os_detection: bool = True,
        script_scan: bool = True,
        vuln_scan: bool = True,
        traceroute: bool = True,
        aggressive: bool = False,
        timing: int = 4,
        timeout: int = 600
    ) -> NmapResult:
        """Advanced deep scan with comprehensive enumeration."""
        self.logger.info(f"Advanced scanning {len(targets)} targets, ports {ports}")

        result = NmapResult(targets=targets, scan_start=datetime.utcnow())

        # Build advanced nmap command
        command = self._build_advanced_command(
            targets,
            ports,
            tcp_scan,
            udp_scan,
            service_detection,
            os_detection,
            script_scan,
            vuln_scan,
            traceroute,
            aggressive,
            timing
        )

        result.command = command
        self.logger.debug(f"Nmap advanced command: {command}")

        try:
            # Execute nmap
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            result.exit_status = process.returncode
            result.scan_end = datetime.utcnow()

            # Parse XML output
            if process.returncode == 0:
                xml_output = stdout.decode()
                result.hosts = self._parse_xml(xml_output)
                self.logger.info(f"Advanced scan complete: {len(result.hosts)} hosts scanned")
            else:
                self.logger.error(f"Nmap advanced scan failed with status {process.returncode}")
                self.logger.error(f"stderr: {stderr.decode()}")

        except asyncio.TimeoutError:
            self.logger.error("Nmap advanced scan timed out")
            result.exit_status = -1
        except Exception as e:
            self.logger.error(f"Nmap advanced scan failed: {e}")
            result.exit_status = -1

        return result

    def _build_advanced_command(
        self,
        targets: List[str],
        ports: str,
        tcp_scan: bool,
        udp_scan: bool,
        service_detection: bool,
        os_detection: bool,
        script_scan: bool,
        vuln_scan: bool,
        traceroute: bool,
        aggressive: bool,
        timing: int
    ) -> List[str]:
        """Build advanced nmap command."""
        cmd = ["nmap"]

        # Scan types - auto-detect based on root privileges
        if tcp_scan and udp_scan:
            if self.is_root:
                cmd.append("-sS")  # SYN scan for TCP (requires root)
            else:
                cmd.append("-sT")  # TCP connect scan (no root required)
            cmd.append("-sU")  # UDP scan
        elif tcp_scan:
            if self.is_root:
                cmd.append("-sS")  # SYN scan (requires root)
            else:
                cmd.append("-sT")  # TCP connect scan (no root required)
        elif udp_scan:
            cmd.append("-sU")  # UDP scan only

        # Port specification
        cmd.append("-p")
        cmd.append(ports)

        # Service detection
        if service_detection:
            cmd.append("-sV")
            cmd.append("--version-intensity")  # Default: 7
            cmd.append("7")

        # OS detection
        if os_detection:
            cmd.append("-O")

        # Script scanning
        if script_scan:
            if vuln_scan:
                # Vulnerability detection scripts
                cmd.append("--script")
                cmd.append("vuln")
            else:
                # Default safe scripts
                cmd.append("--script")
                cmd.append("default,safe")

        # Traceroute
        if traceroute:
            cmd.append("--traceroute")

        # Aggressive scan
        if aggressive:
            cmd.append("-A")

        # Timing template (0-5, 4 is normal)
        cmd.append(f"-T{timing}")

        # XML output
        cmd.append("-oX")
        cmd.append("-")  # stdout

        # Verbosity
        cmd.append("-v")

        # Add targets
        cmd.extend(targets)

        return cmd

    def to_dict(self, result: NmapResult) -> Dict[str, Any]:
        """Convert NmapResult to dictionary."""
        return {
            "targets": result.targets,
            "hosts": [
                {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "state": h.state,
                    "ports": [
                        {
                            "port": p.port,
                            "protocol": p.protocol,
                            "state": p.state,
                            "service": p.service,
                            "version": p.version,
                            "product": p.product,
                            "extra_info": p.extra_info
                        }
                        for p in h.ports
                    ],
                    "os": h.os,
                    "uptime": h.uptime
                }
                for h in result.hosts
            ],
            "scan_start": result.scan_start.isoformat() if result.scan_start else None,
            "scan_end": result.scan_end.isoformat() if result.scan_end else None,
            "command": " ".join(result.command) if isinstance(result.command, list) else result.command,
            "exit_status": result.exit_status
        }
