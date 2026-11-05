"""
HAZARUS API Discovery
API endpoint discovery and analysis.
"""

import asyncio
import logging
import httpx
import json
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlparse
import re


@dataclass
class APIEndpoint:
    """An API endpoint."""
    url: str
    method: str
    path: str
    parameters: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    authentication: Optional[str] = None
    response_codes: List[int] = field(default_factory=list)
    content_type: Optional[str] = None


@dataclass
class APIDiscoveryResult:
    """API discovery result."""
    target: str
    endpoints: List[APIEndpoint] = field(default_factory=list)
    openapi_spec: Optional[Dict[str, Any]] = None
    graphql_endpoints: List[str] = field(default_factory=list)
    rest_endpoints: List[str] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)
    discovered_at: datetime = None

    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.utcnow()


class APIDiscovery:
    """API discovery module."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.logger = logging.getLogger("hazarus.api_discovery")

        # Common API paths
        self.common_api_paths = [
            "/api", "/v1", "/v2", "/api/v1", "/api/v2",
            "/graphql", "/rest", "/ws", "/socket.io",
            "/swagger", "/api-docs", "/openapi.json", "/swagger.json"
        ]

    async def discover(self, target: str) -> APIDiscoveryResult:
        """Discover API endpoints."""
        self.logger.info(f"Discovering APIs for {target}")

        result = APIDiscoveryResult(target=target)

        # Ensure target has protocol
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        try:
            # Check for OpenAPI/Swagger
            await self._check_openapi(target, result)

            # Check for GraphQL
            await self._check_graphql(target, result)

            # Discover REST endpoints
            await self._discover_rest_endpoints(target, result)

            # Check for common API paths
            await self._check_common_paths(target, result)

            # Analyze security
            await self._analyze_security(result)

        except Exception as e:
            self.logger.error(f"API discovery failed: {e}")
            result.security_issues.append(f"Discovery failed: {str(e)}")

        return result

    async def _check_openapi(self, target: str, result: APIDiscoveryResult) -> None:
        """Check for OpenAPI/Swagger specification."""
        openapi_paths = [
            "/swagger.json",
            "/swagger.yaml",
            "/openapi.json",
            "/openapi.yaml",
            "/api-docs",
            "/api/swagger.json",
            "/api/openapi.json"
        ]

        for path in openapi_paths:
            url = urljoin(target, path)
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(url)

                    if response.status_code == 200:
                        try:
                            spec = response.json()
                            result.openapi_spec = spec
                            self.logger.info(f"Found OpenAPI spec at {url}")

                            # Extract endpoints from spec
                            if "paths" in spec:
                                for path, methods in spec["paths"].items():
                                    for method in methods.keys():
                                        endpoint = APIEndpoint(
                                            url=urljoin(target, path),
                                            method=method.upper(),
                                            path=path
                                        )
                                        result.endpoints.append(endpoint)

                        except json.JSONDecodeError:
                            pass

            except Exception:
                pass

    async def _check_graphql(self, target: str, result: APIDiscoveryResult) -> None:
        """Check for GraphQL endpoint."""
        graphql_paths = ["/graphql", "/graphiql", "/api/graphql"]

        for path in graphql_paths:
            url = urljoin(target, path)
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    # Send a simple introspection query
                    query = """
                    query {
                        __schema {
                            types {
                                name
                            }
                        }
                    }
                    """

                    response = await client.post(
                        url,
                        json={"query": query},
                        headers={"Content-Type": "application/json"}
                    )

                    if response.status_code == 200:
                        result.graphql_endpoints.append(url)
                        self.logger.info(f"Found GraphQL endpoint at {url}")

                        # Add as endpoint
                        endpoint = APIEndpoint(
                            url=url,
                            method="POST",
                            path=path,
                            content_type="application/json"
                        )
                        result.endpoints.append(endpoint)

            except Exception:
                pass

    async def _discover_rest_endpoints(self, target: str, result: APIDiscoveryResult) -> None:
        """Discover REST API endpoints through common patterns."""
        # Try common REST patterns
        rest_patterns = [
            "/api/users",
            "/api/posts",
            "/api/products",
            "/api/items",
            "/api/data",
            "/users",
            "/posts",
            "/products"
        ]

        for pattern in rest_patterns:
            url = urljoin(target, pattern)
            for method in ["GET", "POST", "PUT", "DELETE"]:
                try:
                    async with httpx.AsyncClient(timeout=self.timeout) as client:
                        response = await client.request(method, url)

                        if response.status_code in [200, 201, 202, 401, 403]:
                            endpoint = APIEndpoint(
                                url=url,
                                method=method,
                                path=pattern,
                                response_codes=[response.status_code],
                                content_type=response.headers.get("content-type")
                            )
                            result.endpoints.append(endpoint)
                            result.rest_endpoints.append(url)

                except Exception:
                    pass

    async def _check_common_paths(self, target: str, result: APIDiscoveryResult) -> None:
        """Check for common API paths."""
        for path in self.common_api_paths:
            url = urljoin(target, path)
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(url)

                    if response.status_code != 404:
                        endpoint = APIEndpoint(
                            url=url,
                            method="GET",
                            path=path,
                            response_codes=[response.status_code]
                        )
                        result.endpoints.append(endpoint)

            except Exception:
                pass

    async def _analyze_security(self, result: APIDiscoveryResult) -> None:
        """Analyze API security issues."""
        for endpoint in result.endpoints:
            # Check for missing authentication
            if endpoint.authentication is None and endpoint.method in ["POST", "PUT", "DELETE"]:
                result.security_issues.append(
                    f"Endpoint {endpoint.url} ({endpoint.method}) may lack authentication"
                )

            # Check for CORS issues
            if "cors" in endpoint.path.lower():
                result.security_issues.append(
                    f"CORS endpoint detected: {endpoint.url}"
                )

        # Check for exposed OpenAPI spec
        if result.openapi_spec:
            result.security_issues.append("OpenAPI specification is publicly accessible")

        # Check for GraphQL introspection
        if result.graphql_endpoints:
            result.security_issues.append("GraphQL introspection may be enabled")

    def to_dict(self, result: APIDiscoveryResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": result.target,
            "endpoints": [
                {
                    "url": e.url,
                    "method": e.method,
                    "path": e.path,
                    "parameters": e.parameters,
                    "authentication": e.authentication,
                    "response_codes": e.response_codes,
                    "content_type": e.content_type
                }
                for e in result.endpoints
            ],
            "openapi_spec_available": result.openapi_spec is not None,
            "graphql_endpoints": result.graphql_endpoints,
            "rest_endpoints": result.rest_endpoints,
            "security_issues": result.security_issues,
            "discovered_at": result.discovered_at.isoformat()
        }
