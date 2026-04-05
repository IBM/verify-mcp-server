"""MCP tool definitions for IBM Security Verify.

Exposes four meta-tools that cover the entire Verify API surface:
  1. verify_discover      — search endpoints by keyword / category / method
  2. verify_list_categories — list all API categories with endpoint counts
  3. verify_get_api_details — get full parameter schema for a specific endpoint
  4. verify_execute        — execute any Verify API endpoint

This is the same "meta-tool proxy" pattern used by the QRadar, GCM, and GDP
MCP servers — instead of registering 210 individual tools, we register only
four generic tools, reducing per-request token overhead by ~98%.

Token Optimisation Strategy:
  - verify_discover returns max 25 results per page (with pagination)
  - Results are relevance-ranked (exact match > word boundary > substring)
  - ≤3 match queries auto-include full parameter details (saving round-trips)
  - Multi-category results are grouped by domain for easier navigation
  - verify_list_categories groups 89 categories into 9 domains
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

# Maximum results per page for verify_discover
# Show all if ≤ this threshold; paginate beyond it
DEFAULT_PAGE_SIZE = 25


def _truncate(text: str, limit: int = MAX_RESPONSE_LENGTH) -> str:
    """Truncate text if it exceeds the limit."""
    if len(text) <= limit:
        return text
    return text[:limit] + TRUNCATION_MSG.format(limit=limit)


def _format_endpoint_summary(ep: VerifyEndpoint, include_category: bool = False) -> dict[str, str]:
    """Return a summary dict for search results.

    Keeps full description so the LLM has enough context to pick the
    right endpoint.  Category is included when results span multiple
    categories (set *include_category=True*).
    """
    summary: dict[str, str] = {
        "endpoint_id": ep.endpoint_id,
        "method": ep.method,
        "path": ep.path,
    }
    if include_category:
        summary["category"] = ep.category
    summary["description"] = ep.description
    return summary


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
        offset: int = 0,
    ) -> str:
        """Search IBM Security Verify API endpoints by keyword, category, or HTTP method.

        Results are ranked by relevance and grouped by category when spanning
        multiple categories.  If 1-3 matches are found, full parameter details
        are included automatically (no need to call verify_get_api_details).
        Queries with >25 results are paginated — use offset to page through.

        Args:
            query: Keyword to search (e.g., "user", "group", "mfa", "consent")
            category: Optional category filter (e.g., "Users Management", "FIDO2")
            method: Optional HTTP method filter (GET, POST, PUT, PATCH, DELETE)
            offset: Pagination offset — skip this many results (default: 0)

        Returns:
            JSON with matching endpoints grouped by category.  ≤3 matches
            include full parameter/body details.  >25 matches are paginated.
        """
        results = discovery.search(query, category=category, method=method)
        if not results:
            return json.dumps({
                "message": f"No endpoints found matching '{query}'",
                "hint": "Try broader keywords or use verify_list_categories to browse",
                "total_available": discovery.total_endpoints,
            })

        total_matches = len(results)

        # ≤3 matches → auto-include full details (saves round-trips)
        if total_matches <= 3:
            details = [_format_endpoint_detail(ep) for ep in results]
            return json.dumps({
                "matches": total_matches,
                "endpoints": details,
            }, indent=2)

        # Check if results span multiple categories
        categories_seen = {ep.category for ep in results}
        multi_category = len(categories_seen) > 1

        # ≤ page size → return all; otherwise paginate
        if total_matches <= DEFAULT_PAGE_SIZE:
            page = results
        else:
            page = results[offset : offset + DEFAULT_PAGE_SIZE]

        # Group results by category for easier navigation
        if multi_category:
            grouped: dict[str, list[dict]] = {}
            for ep in page:
                summary = _format_endpoint_summary(ep, include_category=False)
                grouped.setdefault(ep.category, []).append(summary)
            response: dict[str, Any] = {
                "matches": total_matches,
                "by_category": grouped,
            }
        else:
            summaries = [_format_endpoint_summary(ep, include_category=False) for ep in page]
            response = {
                "matches": total_matches,
                "category": page[0].category if page else "",
                "endpoints": summaries,
            }

        if total_matches > DEFAULT_PAGE_SIZE:
            response["showing"] = f"{offset + 1}-{offset + len(page)} of {total_matches}"
            if (offset + DEFAULT_PAGE_SIZE) < total_matches:
                response["next_offset"] = offset + DEFAULT_PAGE_SIZE

        return json.dumps(response)

    # ── Tool 2: List categories ─────────────────────────────────────

    @mcp.tool()
    async def verify_list_categories() -> str:
        """List all IBM Security Verify API categories grouped by domain.

        Use this tool to browse the full API surface and identify relevant
        categories before searching with verify_discover.

        Returns:
            JSON object with categories grouped by domain, plus totals.
        """
        cats = discovery.categories
        # Group categories by domain for a more compact, navigable output
        domains: dict[str, dict[str, int]] = {}
        for name, count in sorted(cats.items()):
            # Derive domain from category name heuristics
            name_lower = name.lower()
            if any(k in name_lower for k in ("user", "scim", "group", "bulk", "identity", "dynamic group", "self care")):
                domain = "Identity"
            elif any(k in name_lower for k in ("otp", "mfa", "fido", "totp", "qr", "knowledge", "signature", "authenticat", "recaptcha", "smartcard", "x.509")):
                domain = "MFA"
            elif any(k in name_lower for k in ("saml", "federation", "oidc", "wsfed", "ws-fed", "social", "jwt")):
                domain = "Federation"
            elif any(k in name_lower for k in ("access", "polic", "entitlement", "session")):
                domain = "Access & Policy"
            elif any(k in name_lower for k in ("consent", "privacy", "dpcm", "purpose", "data subject")):
                domain = "Privacy & Consent"
            elif any(k in name_lower for k in ("event", "report", "log", "webhook", "threat", "itdr")):
                domain = "Operations"
            elif any(k in name_lower for k in ("campaign", "certification", "governance")):
                domain = "Governance"
            elif any(k in name_lower for k in ("password", "dictionary", "tenant", "theme", "template", "client", "config", "adapter", "provisioning", "certificate", "push", "email sup")):
                domain = "Configuration"
            else:
                domain = "Other"
            domains.setdefault(domain, {})[name] = count

        # Build compact output: domain → {category: count}
        output = json.dumps({
            "total_categories": len(cats),
            "total_endpoints": discovery.total_endpoints,
            "domains": domains,
        })
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
