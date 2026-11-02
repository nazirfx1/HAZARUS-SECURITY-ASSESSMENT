"""
HAZARUS HTTP Scanner
HTTP security scanning.
"""

import asyncio
import logging
import httpx
import subprocess
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse


@dataclass
class SecurityHeader:
    """Security header information."""
    name: str
    present: bool
    value: Optional[str] = None
    severity: str = "info"  # info, warning, critical


@dataclass
class HTTPSecurityResult:
    """HTTP security scan result."""
    target: str
    security_headers: List[SecurityHeader] = field(default_factory=list)
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    cors_config: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    scanned_at: datetime = None

    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class HTTPScanner:
    """HTTP scanning module."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.logger = logging.getLogger("hazarus.http_scanner")

        # Important security headers
        self.security_headers = {
            "Strict-Transport-Security": {"severity": "critical", "description": "HSTS"},
            "Content-Security-Policy": {"severity": "critical", "description": "CSP"},
            "X-Frame-Options": {"severity": "warning", "description": "Clickjacking protection"},
            "X-Content-Type-Options": {"severity": "info", "description": "MIME sniffing"},
            "X-XSS-Protection": {"severity": "warning", "description": "XSS filter"},
            "Referrer-Policy": {"severity": "info", "description": "Referrer control"},
            "Permissions-Policy": {"severity": "info", "description": "Feature policy"},
            "Cross-Origin-Opener-Policy": {"severity": "info", "description": "COOP"},
            "Cross-Origin-Resource-Policy": {"severity": "info", "description": "CORP"},
        }

    async def scan(self, target: str) -> HTTPSecurityResult:
        """Scan HTTP target."""
        self.logger.info(f"Scanning HTTP target {target}")

        result = HTTPSecurityResult(target=target)

        # Ensure target has protocol
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(target)
                headers = dict(response.headers)

                # Check security headers
                await self._check_security_headers(headers, result)

                # Analyze cookies
                await self._analyze_cookies(headers, result)

                # Check CORS configuration
                await self._check_cors(headers, result)

                # Check for common vulnerabilities
                await self._check_vulnerabilities(response, result)

                # Generate recommendations
                self._generate_recommendations(result)

            # Run Nikto scan if available
            nikto_results = await self._run_nikto(target)
            if nikto_results:
                result.vulnerabilities.extend(nikto_results)

        except httpx.ConnectError as e:
            self.logger.error(f"HTTP scan failed - connection error: {e}")
            result.vulnerabilities.append(f"Connection failed: {str(e)}")
            result.vulnerabilities.append("Check if target is accessible and DNS is resolving")
        except httpx.TimeoutException as e:
            self.logger.error(f"HTTP scan failed - timeout: {e}")
            result.vulnerabilities.append(f"Request timed out: {str(e)}")
        except httpx.HTTPStatusError as e:
            self.logger.error(f"HTTP scan failed - status error: {e}")
            result.vulnerabilities.append(f"HTTP error: {e.response.status_code}")
        except Exception as e:
            self.logger.error(f"HTTP scan failed: {e}")
            result.vulnerabilities.append(f"Scan failed: {str(e)}")
            result.vulnerabilities.append(f"Error type: {type(e).__name__}")

        return result

    async def _run_nikto(self, target: str) -> List[str]:
        """Run Nikto web vulnerability scanner if available."""
        try:
            # Check if Nikto is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "nikto",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                self.logger.info("Nikto not installed, skipping Nikto scan")
                return []

            # Run Nikto scan
            self.logger.info(f"Running Nikto scan on {target}")
            proc = await asyncio.create_subprocess_exec(
                "nikto",
                "-h", target,
                "-Tuning", "1",  # Show 1-200, 301, 307
                "-Display", "V",  # Vulnerable items only
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            output = stdout.decode()
            vulnerabilities = []
            
            # Parse Nikto output for vulnerabilities
            for line in output.split('\n'):
                if line.strip() and ('+' in line or '-' in line):
                    vulnerabilities.append(f"Nikto: {line.strip()}")
            
            if vulnerabilities:
                self.logger.info(f"Nikto found {len(vulnerabilities)} potential issues")
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.warning(f"Nikto scan failed: {e}")
            return []

    async def _check_security_headers(self, headers: Dict[str, str], result: HTTPSecurityResult) -> None:
        """Check for security headers."""
        for header_name, config in self.security_headers.items():
            header_info = SecurityHeader(
                name=header_name,
                present=header_name in headers,
                value=headers.get(header_name),
                severity=config["severity"]
            )
            result.security_headers.append(header_info)

            if not header_info.present:
                result.vulnerabilities.append(f"Missing security header: {config['description']}")

    async def _analyze_cookies(self, headers: Dict[str, str], result: HTTPSecurityResult) -> None:
        """Analyze cookies for security issues."""
        set_cookie = headers.get("set-cookie", "")

        if set_cookie:
            cookies = set_cookie.split(";")
            for cookie in cookies:
                cookie_info = {"name": cookie.split("=")[0] if "=" in cookie else cookie}

                # Check for Secure flag
                if "Secure" not in cookie:
                    cookie_info["secure"] = False
                    result.vulnerabilities.append(f"Cookie missing Secure flag: {cookie_info['name']}")

                # Check for HttpOnly flag
                if "HttpOnly" not in cookie:
                    cookie_info["httponly"] = False
                    result.vulnerabilities.append(f"Cookie missing HttpOnly flag: {cookie_info['name']}")

                # Check for SameSite
                if "SameSite" not in cookie:
                    cookie_info["samesite"] = False
                    result.vulnerabilities.append(f"Cookie missing SameSite attribute: {cookie_info['name']}")

                result.cookies.append(cookie_info)

    async def _check_cors(self, headers: Dict[str, str], result: HTTPSecurityResult) -> None:
        """Check CORS configuration."""
        cors_headers = {
            "Access-Control-Allow-Origin": headers.get("Access-Control-Allow-Origin"),
            "Access-Control-Allow-Methods": headers.get("Access-Control-Allow-Methods"),
            "Access-Control-Allow-Headers": headers.get("Access-Control-Allow-Headers"),
            "Access-Control-Allow-Credentials": headers.get("Access-Control-Allow-Credentials"),
        }

        result.cors_config = {k: v for k, v in cors_headers.items() if v is not None}

        # Check for overly permissive CORS
        if cors_headers["Access-Control-Allow-Origin"] == "*":
            result.vulnerabilities.append("Overly permissive CORS: allows any origin")

    async def _check_vulnerabilities(self, response: httpx.Response, result: HTTPSecurityResult) -> None:
        """Check for common HTTP vulnerabilities."""
        # Check for server header disclosure
        server = response.headers.get("server", "")
        if server:
            result.vulnerabilities.append(f"Server header discloses version: {server}")

        # Check for X-Powered-By disclosure
        powered_by = response.headers.get("x-powered-by", "")
        if powered_by:
            result.vulnerabilities.append(f"X-Powered-By header discloses technology: {powered_by}")

        # Check for missing charset
        content_type = response.headers.get("content-type", "")
        if "charset" not in content_type.lower():
            result.vulnerabilities.append("Content-Type missing charset specification")

    def _generate_recommendations(self, result: HTTPSecurityResult) -> None:
        """Generate security recommendations."""
        missing_critical = [h for h in result.security_headers if not h.present and h.severity == "critical"]
        if missing_critical:
            result.recommendations.append("Implement critical security headers (HSTS, CSP)")

        if result.cookies:
            insecure_cookies = [c for c in result.cookies if not c.get("secure", True)]
            if insecure_cookies:
                result.recommendations.append("Add Secure and HttpOnly flags to sensitive cookies")

        if result.cors_config.get("Access-Control-Allow-Origin") == "*":
            result.recommendations.append("Restrict CORS to specific origins instead of wildcard")

    def to_dict(self, result: HTTPSecurityResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": result.target,
            "security_headers": [
                {
                    "name": h.name,
                    "present": h.present,
                    "value": h.value,
                    "severity": h.severity
                }
                for h in result.security_headers
            ],
            "cookies": result.cookies,
            "cors_config": result.cors_config,
            "vulnerabilities": result.vulnerabilities,
            "recommendations": result.recommendations,
            "scanned_at": result.scanned_at.isoformat()
        }
