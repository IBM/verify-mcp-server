"""MCP tool definitions for IBM Security Verify.

Exposes four meta-tools that cover the entire Verify API surface:
  1. verify_discover      — search endpoints by keyword / category / method
  2. verify_list_categories — list all API categories with endpoint counts
  3. verify_get_api_details — get full parameter schema for a specific endpoint
  4. verify_execute        — execute any Verify API endpoint

This is the same "meta-tool proxy" pattern used by the QRadar, GCM, and GDP
MCP servers — instead of registering 200+ individual tools, we register only
four generic tools, reducing per-request token overhead by ~98%.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from .client import VerifyClient
from .discovery import VerifyDiscovery, VerifyEndpoint

logger = logging.getLogger(__name__)

# Maximum characters in a tool response before truncation
MAX_RESPONSE_LENGTH = 50_000
TRUNCATION_MSG = "\n\n⚠️ Response truncated at {limit} characters. Use filters or pagination to narrow results."


def _truncate(text: str, limit: int = MAX_RESPONSE_LENGTH) -> str:
    """Truncate text if it exceeds the limit."""
    if len(text) <= limit:
        return text
    return text[:limit] + TRUNCATION_MSG.format(limit=limit)


def _format_endpoint_summary(ep: VerifyEndpoint) -> dict[str, str]:
    """Return a compact summary dict for search results."""
    return {
        "endpoint_id": ep.endpoint_id,
        "method": ep.method,
        "path": ep.path,
        "category": ep.category,
        "description": ep.description,
    }


def _format_endpoint_detail(ep: VerifyEndpoint) -> dict[str, Any]:
    """Return full parameter schema for an endpoint."""
    detail: dict[str, Any] = {
        "endpoint_id": ep.endpoint_id,
        "method": ep.method,
        "path": ep.path,
        "category": ep.category,
        "description": ep.description,
    }
    if ep.params:
        detail["params"] = ep.params
    if ep.body:
        detail["body"] = ep.body
    if ep.required_params:
        detail["required"] = ep.required_params
    return detail


def _resolve_path(path_template: str, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Replace {placeholders} in path with values from params.

    Returns the resolved path and the remaining params that were
    NOT consumed as path parameters.
    """
    import re

    remaining = dict(params)
    resolved = path_template
    for match in re.findall(r"\{(\w+)\}", path_template):
        if match in remaining:
            resolved = resolved.replace(f"{{{match}}}", str(remaining.pop(match)))
        else:
            logger.warning("Path parameter '%s' not provided for %s", match, path_template)
    return resolved, remaining


def register_tools(
    mcp: FastMCP,
    client: VerifyClient,
    discovery: VerifyDiscovery,
) -> None:
    """Register the four Verify meta-tools on the MCP server."""

    # ── Tool 1: Discover endpoints ──────────────────────────────────

    @mcp.tool()
    async def verify_discover(
        query: str,
        category: str | None = None,
        method: str | None = None,
    ) -> str:
        """Search IBM Security Verify API endpoints by keyword, category, or HTTP method.

        Use this tool FIRST to find which endpoints are available before
        calling verify_get_api_details or verify_execute.

        Args:
            query: Keyword to search in endpoint names, paths, and descriptions
                   (e.g., "user", "group", "mfa", "consent", "token")
            category: Optional category filter (e.g., "Users Management", "FIDO2")
            method: Optional HTTP method filter (GET, POST, PUT, PATCH, DELETE)

        Returns:
            JSON array of matching endpoints with endpoint_id, method, path,
            category, and description.
        """
        results = discovery.search(query, category=category, method=method)
        if not results:
            return json.dumps({
                "message": f"No endpoints found matching '{query}'",
                "hint": "Try broader keywords or use verify_list_categories to browse",
                "total_available": discovery.total_endpoints,
            })
        summaries = [_format_endpoint_summary(ep) for ep in results]
        output = json.dumps({
            "matches": len(summaries),
            "total_available": discovery.total_endpoints,
            "endpoints": summaries,
        }, indent=2)
        return _truncate(output)

    # ── Tool 2: List categories ─────────────────────────────────────

    @mcp.tool()
    async def verify_list_categories() -> str:
        """List all IBM Security Verify API categories and the number of endpoints in each.

        Use this tool to browse the full API surface and identify relevant
        categories before searching with verify_discover.

        Returns:
            JSON object with categories (name → endpoint count) and totals.
        """
        cats = discovery.categories
        output = json.dumps({
            "total_categories": len(cats),
            "total_endpoints": discovery.total_endpoints,
            "categories": {name: count for name, count in sorted(cats.items())},
        }, indent=2)
        return _truncate(output)

    # ── Tool 3: Get API details ─────────────────────────────────────

    @mcp.tool()
    async def verify_get_api_details(endpoint_id: str) -> str:
        """Get the full parameter schema for a specific IBM Security Verify API endpoint.

        Call this AFTER using verify_discover to find the endpoint_id.
        Returns all parameters, body fields, required fields, and usage hints.

        Args:
            endpoint_id: The unique endpoint identifier (e.g., "getUsers", "createUser")

        Returns:
            JSON object with method, path, parameters, body schema, and required fields.
        """
        ep = discovery.get_endpoint(endpoint_id)
        if not ep:
            # Try fuzzy match
            possible = [
                eid for eid in discovery.endpoints
                if endpoint_id.lower() in eid.lower()
            ]
            return json.dumps({
                "error": f"Endpoint '{endpoint_id}' not found",
                "suggestions": possible[:10] if possible else [],
                "hint": "Use verify_discover to search for the correct endpoint_id",
            })
        detail = _format_endpoint_detail(ep)
        return json.dumps(detail, indent=2)

    # ── Tool 4: Execute API endpoint ────────────────────────────────

    @mcp.tool()
    async def verify_execute(
        endpoint_id: str,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> str:
        """Execute any IBM Security Verify API endpoint.

        IMPORTANT: Call verify_get_api_details first to understand required
        parameters and body fields before executing.

        Args:
            endpoint_id: The endpoint to execute (e.g., "getUsers", "createUser")
            params: Query parameters and path parameters as key-value pairs.
                    Path parameters like {id} are automatically substituted.
            body: Request body (JSON) for POST/PUT/PATCH methods.

        Returns:
            JSON response from the IBM Security Verify API, or error details.
        """
        ep = discovery.get_endpoint(endpoint_id)
        if not ep:
            return json.dumps({
                "error": f"Endpoint '{endpoint_id}' not found",
                "hint": "Use verify_discover to find the correct endpoint_id",
            })

        params = params or {}
        body = body or {}

        # Resolve path parameters
        resolved_path, remaining_params = _resolve_path(ep.path, params)

        # Content-Type for SCIM is handled automatically in VerifyClient
        content_type = None

        try:
            result = await client.request(
                method=ep.method,
                endpoint=resolved_path,
                params=remaining_params if remaining_params else None,
                body=body if body else None,
                content_type=content_type,
            )
            output = json.dumps(result, indent=2, default=str)
            return _truncate(output)
        except Exception as e:
            logger.exception("Error executing %s %s", ep.method, resolved_path)
            return json.dumps({
                "error": str(e),
                "endpoint": endpoint_id,
                "method": ep.method,
                "path": resolved_path,
            })
