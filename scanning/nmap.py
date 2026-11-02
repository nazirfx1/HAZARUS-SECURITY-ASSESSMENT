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

    async def scan(
        self,
        targets: List[str],
        ports: str = "1-1000",
        scan_type: str = "sT",  # sT (TCP connect), sS (SYN)
        service_detection: bool = True,
        os_detection: bool = False,
        aggressive: bool = False,
        timeout: int = 300
    ) -> NmapResult:
        """Scan targets with Nmap."""
        self.logger.info(f"Scanning {len(targets)} targets, ports {ports}")

        result = NmapResult(targets=targets, scan_start=datetime.utcnow())

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
            loop = asyncio.get_event_loop()
            process = await asyncio.create_subprocess_exec(
                *command.split(),
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
    ) -> str:
        """Build nmap command."""
        cmd = ["nmap"]

        # Scan type
        if scan_type == "sS":
            cmd.append("-sS")
        else:
            cmd.append("-sT")  # Default to TCP connect (no root required)

        # Port specification
        cmd.append(f"-p{ports}")

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

        return " ".join(cmd)

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

        command = f"nmap -sT --open -oX - {target}"

        try:
            loop = asyncio.get_event_loop()
            process = await asyncio.create_subprocess_exec(
                *command.split(),
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
            "command": result.command,
            "exit_status": result.exit_status
        }
