"""
HAZARUS HTTP Scanner
HTTP security scanning.
"""

import asyncio
import logging
import httpx
import subprocess
import json
import time
import os
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
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    open_directories: List[str] = field(default_factory=list)
    waf_detected: Optional[str] = None
    nuclei_findings: List[str] = field(default_factory=list)
    sqlmap_findings: List[str] = field(default_factory=list)
    ssl_labs_score: Optional[str] = None
    ssl_labs_grade: Optional[str] = None
    scan_duration: float = 0.0  # Scan duration in seconds
    dns_resolution_time: float = 0.0
    connection_time: float = 0.0
    response_time: float = 0.0

    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class HTTPScanner:
    """HTTP scanning module."""

    def __init__(self, timeout: int = 10, connect_timeout: int = 5, skip_advanced: bool = False):
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.skip_advanced = skip_advanced
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
        scan_start = time.time()

        # Ensure target has protocol
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        try:
            dns_start = time.time()
            self.logger.info(f"Resolving DNS for {target}...")
            
            # Use separate timeout for connection
            timeout = httpx.Timeout(
                connect=self.connect_timeout,
                read=self.timeout,
                write=self.timeout,
                pool=self.timeout
            )
            
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                dns_end = time.time()
                result.dns_resolution_time = dns_end - dns_start
                self.logger.info(f"DNS resolved in {result.dns_resolution_time:.2f}s")
                
                conn_start = time.time()
                self.logger.info(f"Establishing connection to {target} (timeout: {self.connect_timeout}s)...")
                
                try:
                    response = await client.get(target)
                except httpx.TimeoutException as e:
                    self.logger.error(f"Connection timeout after {self.connect_timeout}s")
                    result.vulnerabilities.append(f"Connection timeout: Server did not respond within {self.connect_timeout}s")
                    result.vulnerabilities.append("Possible causes: Firewall, WAF blocking, or server is down")
                    result.vulnerabilities.append("Try increasing timeout or checking network connectivity")
                    return result
                
                conn_end = time.time()
                result.connection_time = conn_end - conn_start
                result.response_time = conn_end - dns_start
                self.logger.info(f"Connection established in {result.connection_time:.2f}s (total: {result.response_time:.2f}s)")
                
                headers = dict(response.headers)
                self.logger.info(f"HTTP response received: {response.status_code} {response.reason_phrase}")

                # Check security headers
                self.logger.info("Checking security headers...")
                await self._check_security_headers(headers, result)

                # Analyze cookies
                self.logger.info("Analyzing cookies...")
                await self._analyze_cookies(headers, result)

                # Check CORS configuration
                self.logger.info("Checking CORS configuration...")
                await self._check_cors(headers, result)

                # Check for common vulnerabilities
                self.logger.info("Checking for common vulnerabilities...")
                await self._check_vulnerabilities(response, result)

                # Generate recommendations
                self.logger.info("Generating recommendations...")
                self._generate_recommendations(result)

                # Run advanced scans (optional, don't fail on errors)
                if not self.skip_advanced:
                    try:
                        self.logger.info("Running SSL/TLS analysis...")
                        await self._analyze_ssl(target, result)
                    except Exception as e:
                        self.logger.warning(f"SSL analysis skipped: {e}")
                    
                    try:
                        self.logger.info("Detecting technologies...")
                        await self._detect_technologies(headers, response, result)
                    except Exception as e:
                        self.logger.warning(f"Technology detection skipped: {e}")
                    
                    try:
                        self.logger.info("Checking for WAF...")
                        await self._detect_waf(headers, result)
                    except Exception as e:
                        self.logger.warning(f"WAF detection skipped: {e}")
                    
                    try:
                        self.logger.info("Scanning for open directories...")
                        await self._scan_directories(target, result)
                    except Exception as e:
                        self.logger.warning(f"Directory scan skipped: {e}")
                else:
                    self.logger.info("Advanced scans skipped (--skip-advanced flag)")

            # Run external tool scans
            self.logger.info("Checking for Nuclei scanner...")
            nuclei_results = await self._run_nuclei(target)
            if nuclei_results:
                result.nuclei_findings.extend(nuclei_results)
                self.logger.info(f"Nuclei scan complete: {len(nuclei_results)} findings")
            
            # Run SQLMap scan if available
            self.logger.info("Checking for SQLMap scanner...")
            sqlmap_results = await self._run_sqlmap(target)
            if sqlmap_results:
                result.sqlmap_findings.extend(sqlmap_results)
                self.logger.info(f"SQLMap scan complete: {len(sqlmap_results)} findings")
            
            # Run SSL Labs API scan if available
            self.logger.info("Checking SSL Labs API...")
            ssl_labs_result = await self._check_ssllabs(target)
            if ssl_labs_result:
                result.ssl_labs_score = ssl_labs_result.get("score")
                result.ssl_labs_grade = ssl_labs_result.get("grade")
                self.logger.info(f"SSL Labs grade: {result.ssl_labs_grade}")
            
            # Run Nikto scan if available
            self.logger.info("Checking for Nikto scanner...")
            nikto_results = await self._run_nikto(target)
            if nikto_results:
                result.vulnerabilities.extend(nikto_results)
                self.logger.info(f"Nikto scan complete: {len(nikto_results)} findings")

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

        scan_end = time.time()
        result.scan_duration = scan_end - scan_start
        self.logger.info(f"Total scan duration: {result.scan_duration:.2f}s")

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

            # Run Nikto scan with proxy support for Cloudflare bypass
            self.logger.info(f"Running Nikto scan on {target}")
            
            # Try to get proxy from environment if available
            http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
            https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
            
            nikto_args = [
                "nikto",
                "-h", target,
                "-Tuning", "1",  # Show 1-200, 301, 307
                "-Display", "V",  # Vulnerable items only
                "-no404",  # Don't show 404 responses
                "-T", "x",  # Show testing options
            ]
            
            # Add proxy if available
            if http_proxy:
                nikto_args.extend(["-useproxy", http_proxy])
            
            proc = await asyncio.create_subprocess_exec(
                *nikto_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            output = stdout.decode()
            vulnerabilities = []
            
            # Parse Nikto output for vulnerabilities (only show findings, not init messages)
            for line in output.split('\n'):
                line = line.strip()
                # Skip initialization messages
                if line.startswith('V:') or line.startswith('+ [999') or line.startswith('- STATUS'):
                    continue
                # Only show actual findings
                if line.startswith('+') and ('OSVDB' in line or 'CVE' in line or 'XSS' in line or 'SQL' in line or 'injection' in line.lower()):
                    vulnerabilities.append(f"Nikto: {line}")
                # Show security header findings
                elif line.startswith('+ [013') or line.startswith('+ [9999'):
                    vulnerabilities.append(f"Nikto: {line}")
            
            if vulnerabilities:
                self.logger.info(f"Nikto found {len(vulnerabilities)} potential issues")
            else:
                self.logger.info("Nikto scan complete - no critical findings")
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.warning(f"Nikto scan failed: {e}")
            return []

    async def _run_sqlmap(self, target: str) -> List[str]:
        """Run SQLMap for SQL injection testing if available."""
        try:
            # Check if SQLMap is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "sqlmap",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                self.logger.info("SQLMap not installed, skipping SQL injection scan")
                return []

            # Run SQLMap scan (basic level, no invasive tests)
            self.logger.info(f"Running SQLMap scan on {target}")
            proc = await asyncio.create_subprocess_exec(
                "sqlmap",
                "-u", target,
                "--batch",
                "--level=1",
                "--risk=1",
                "--random-agent",
                "--timeout=10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            output = stdout.decode()
            findings = []
            
            # Parse SQLMap output for injection findings
            for line in output.split('\n'):
                if "sql injection" in line.lower() or "injectable" in line.lower():
                    findings.append(f"SQLMap: {line.strip()}")
            
            if findings:
                self.logger.info(f"SQLMap found {len(findings)} potential SQL injection points")
            else:
                self.logger.info("SQLMap scan complete - no SQL injection found")
            
            return findings
            
        except Exception as e:
            self.logger.warning(f"SQLMap scan failed: {e}")
            return []

    async def _check_ssllabs(self, target: str) -> Dict[str, Any]:
        """Check SSL Labs API for SSL configuration grade."""
        try:
            # Extract hostname from target
            from urllib.parse import urlparse
            parsed = urlparse(target)
            hostname = parsed.netloc.split(":")[0]
            
            # Check for SSL Labs API key
            api_key = os.environ.get("SSLLABS_API_KEY")
            if not api_key:
                self.logger.info("SSL Labs API key not set, skipping SSL Labs scan")
                return {}
            
            # Call SSL Labs API
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"https://api.ssllabs.com/api/v3/analyze?host={hostname}&apiKey={api_key}"
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "score": data.get("endpoints", [{}])[0].get("score", 0),
                        "grade": data.get("endpoints", [{}])[0].get("grade", "N/A")
                    }
                else:
                    self.logger.warning(f"SSL Labs API returned status {response.status_code}")
                    return {}
                    
        except Exception as e:
            self.logger.warning(f"SSL Labs check failed: {e}")
            return {}

    async def _analyze_ssl(self, target: str, result: HTTPSecurityResult) -> None:
        """Analyze SSL/TLS configuration."""
        try:
            # Extract hostname from target
            from urllib.parse import urlparse
            parsed = urlparse(target)
            hostname = parsed.netloc.split(":")[0]
            
            # Use openssl s_client to get SSL info
            proc = await asyncio.create_subprocess_exec(
                "openssl", "s_client", "-connect", f"{hostname}:443",
                "-servername", hostname,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            output = stdout.decode()
            
            # Extract SSL info with better parsing
            if "Protocol" in output:
                for line in output.split('\n'):
                    line = line.strip()
                    if line.startswith("Protocol"):
                        parts = line.split(":")
                        if len(parts) >= 2:
                            result.ssl_info["protocol"] = parts[1].strip()
                    elif line.startswith("Cipher"):
                        parts = line.split(":")
                        if len(parts) >= 2:
                            result.ssl_info["cipher"] = parts[1].strip()
                    elif "Verify return code" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            result.ssl_info["verify_code"] = parts[1].strip()
            
            if result.ssl_info:
                self.logger.info(f"SSL/TLS analysis complete: {result.ssl_info}")
            else:
                self.logger.info("SSL/TLS analysis completed but no info extracted")
                
        except Exception as e:
            self.logger.warning(f"SSL analysis failed: {e}")
            self.logger.warning("SSL analysis is optional, continuing with other checks")

    async def _detect_technologies(self, headers: Dict[str, str], response: httpx.Response, result: HTTPSecurityResult) -> None:
        """Detect technologies used by the target."""
        technologies = []
        
        # Check headers for technology indicators
        server = headers.get("server", "").lower()
        if "nginx" in server:
            technologies.append("Nginx")
        if "apache" in server:
            technologies.append("Apache")
        if "iis" in server:
            technologies.append("IIS")
        if "cloudflare" in server:
            technologies.append("Cloudflare")
        
        powered_by = headers.get("x-powered-by", "").lower()
        if "php" in powered_by:
            technologies.append("PHP")
        if "asp.net" in powered_by:
            technologies.append("ASP.NET")
        if "express" in powered_by:
            technologies.append("Express")
        if "django" in powered_by:
            technologies.append("Django")
        if "flask" in powered_by:
            technologies.append("Flask")
        
        # Check response body for indicators
        content = response.text.lower()
        if "wordpress" in content:
            technologies.append("WordPress")
        if "drupal" in content:
            technologies.append("Drupal")
        if "joomla" in content:
            technologies.append("Joomla")
        if "react" in content:
            technologies.append("React")
        if "vue" in content:
            technologies.append("Vue.js")
        if "angular" in content:
            technologies.append("Angular")
        
        result.technologies = list(set(technologies))
        if result.technologies:
            self.logger.info(f"Technologies detected: {result.technologies}")

    async def _detect_waf(self, headers: Dict[str, str], result: HTTPSecurityResult) -> None:
        """Detect Web Application Firewall (WAF)."""
        waf_indicators = {
            "cloudflare": "Cloudflare WAF",
            "aws": "AWS WAF",
            "akamai": "Akamai WAF",
            "fastly": "Fastly WAF",
            "incapsula": "Incapsula WAF",
            "sucuri": "Sucuri WAF",
            "modsecurity": "ModSecurity",
            "x-sucuri-id": "Sucuri WAF",
            "cf-ray": "Cloudflare",
            "x-amz-cf-id": "AWS CloudFront"
        }
        
        for key, value in headers.items():
            key_lower = key.lower()
            value_lower = value.lower()
            
            for indicator, waf_name in waf_indicators.items():
                if indicator in key_lower or indicator in value_lower:
                    result.waf_detected = waf_name
                    self.logger.info(f"WAF detected: {waf_name}")
                    return

    async def _scan_directories(self, target: str, result: HTTPSecurityResult) -> None:
        """Scan for common open directories."""
        common_dirs = [
            "/admin", "/administrator", "/wp-admin", "/login", "/config",
            "/backup", "/db", "/sql", "/uploads", "/files", "/tmp",
            "/.git", "/.env", "/api", "/test", "/debug"
        ]
        
        async with httpx.AsyncClient(timeout=3) as client:
            for directory in common_dirs:
                try:
                    url = target.rstrip("/") + directory
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        result.open_directories.append(f"{directory} ({response.status_code})")
                        self.logger.info(f"Found open directory: {directory}")
                    elif response.status_code == 403:
                        result.open_directories.append(f"{directory} (403 Forbidden)")
                        self.logger.info(f"Found restricted directory: {directory}")
                        
                except Exception:
                    continue
        
        if result.open_directories:
            self.logger.info(f"Directory scan complete: {len(result.open_directories)} directories found")

    async def _run_nuclei(self, target: str) -> List[str]:
        """Run Nuclei vulnerability scanner if available."""
        try:
            # Check if Nuclei is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "nuclei",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                self.logger.info("Nuclei not installed, skipping Nuclei scan")
                return []

            # Run Nuclei scan
            self.logger.info(f"Running Nuclei scan on {target}")
            proc = await asyncio.create_subprocess_exec(
                "nuclei",
                "-u", target,
                "-severity", "critical,high,medium",
                "-json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            output = stdout.decode()
            findings = []
            
            # Parse Nuclei JSON output
            for line in output.split('\n'):
                if line.strip():
                    try:
                        finding = json.loads(line)
                        template_id = finding.get("templateID", "unknown")
                        severity = finding.get("info", {}).get("severity", "unknown")
                        name = finding.get("info", {}).get("name", "unknown")
                        findings.append(f"Nuclei [{severity}] {name} ({template_id})")
                    except json.JSONDecodeError:
                        pass
            
            if findings:
                self.logger.info(f"Nuclei found {len(findings)} vulnerabilities")
            
            return findings
            
        except Exception as e:
            self.logger.warning(f"Nuclei scan failed: {e}")
            return []

    async def _check_security_headers(self, headers: Dict[str, str], result: HTTPSecurityResult) -> None:
        """Check for security headers."""
        # Normalize headers to lowercase for case-insensitive matching
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header_name, config in self.security_headers.items():
            header_name_lower = header_name.lower()
            present = header_name_lower in headers_lower
            value = headers_lower.get(header_name_lower) if present else None
            
            header_info = SecurityHeader(
                name=header_name,
                present=present,
                value=value,
                severity=config["severity"]
            )
            result.security_headers.append(header_info)

            if not header_info.present:
                result.vulnerabilities.append(f"Missing security header: {config['description']}")

    async def _analyze_cookies(self, headers: Dict[str, str], result: HTTPSecurityResult) -> None:
        """Analyze cookies for security issues."""
        set_cookie = headers.get("set-cookie", "")
        
        if set_cookie:
            # Split by semicolon to separate multiple cookies
            # Cookies are separated by comma in Set-Cookie header
            cookies_list = []
            current_cookie = ""
            
            for part in set_cookie.split(","):
                # Check if this part starts a new cookie (has an = before any other attributes)
                # Cookie attributes like HttpOnly, Secure, Path don't have =
                if "=" in part and part.index("=") < part.index("=") + 1:
                    # This is a new cookie
                    if current_cookie:
                        cookies_list.append(current_cookie.strip())
                    current_cookie = part
                else:
                    # This is an attribute, append to current cookie
                    current_cookie += "," + part
            
            if current_cookie:
                cookies_list.append(current_cookie.strip())
            
            for cookie_str in cookies_list:
                # Parse cookie: name=value; attributes
                cookie_parts = cookie_str.split(";")
                if not cookie_parts:
                    continue
                
                # First part is name=value
                name_value = cookie_parts[0].strip()
                if "=" not in name_value:
                    continue
                
                cookie_name = name_value.split("=")[0].strip()
                cookie_info = {"name": cookie_name}
                
                # Check attributes
                has_secure = "Secure" in cookie_str
                has_httponly = "HttpOnly" in cookie_str
                has_samesite = "SameSite" in cookie_str
                
                if not has_secure:
                    cookie_info["secure"] = False
                    result.vulnerabilities.append(f"Cookie missing Secure flag: {cookie_name}")
                
                if not has_httponly:
                    cookie_info["httponly"] = False
                    result.vulnerabilities.append(f"Cookie missing HttpOnly flag: {cookie_name}")
                
                if not has_samesite:
                    cookie_info["samesite"] = False
                    result.vulnerabilities.append(f"Cookie missing SameSite attribute: {cookie_name}")
                
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
