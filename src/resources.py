"""MCP Resources for IBM Security Verify.

Provides read-only data surfaces for MCP clients:
  1. verify://categories   — API categories with endpoint counts
  2. verify://endpoints/{endpoint_id} — Full details for a specific endpoint (template)
  3. verify://server/info  — Server version, capabilities, feature summary
  4. verify://tenant       — Tenant connection details and OAuth status
"""

from __future__ import annotations

import json
import logging

from mcp.server.fastmcp import Context, FastMCP

from .config import VerifyConfig
from .discovery import VerifyDiscovery

logger = logging.getLogger(__name__)


def register_resources(
    mcp: FastMCP,
    config: VerifyConfig,
    discovery: VerifyDiscovery,
) -> None:
    """Register all Verify MCP resources."""

    # ── Resource 1: API Categories ──────────────────────────────────

    @mcp.resource(
        "verify://categories",
        name="verify_categories",
        title="Verify API Categories",
        description="All IBM Security Verify API categories with endpoint counts.",
        mime_type="application/json",
    )
    async def get_categories() -> str:
        cats = discovery.categories
        return json.dumps({
            "total_categories": len(cats),
            "total_endpoints": discovery.total_endpoints,
            "categories": dict(sorted(cats.items())),
        }, indent=2)

    # ── Resource 2: Endpoint Details (URI Template) ─────────────────

    @mcp.resource(
        "verify://endpoints/{endpoint_id}",
        name="verify_endpoint_details",
        title="Verify Endpoint Details",
        description="Full parameter schema for a specific IBM Security Verify API endpoint.",
        mime_type="application/json",
    )
    async def get_endpoint_details(endpoint_id: str) -> str:
        ep = discovery.get_endpoint(endpoint_id)
        if not ep:
            return json.dumps({"error": f"Endpoint '{endpoint_id}' not found"})
        detail = {
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
        return json.dumps(detail, indent=2)

    # ── Resource 3: Server Info ─────────────────────────────────────

    @mcp.resource(
        "verify://server/info",
        name="verify_server_info",
        title="Verify MCP Server Info",
        description="Server version, protocol, feature capabilities, and tenant target.",
        mime_type="application/json",
    )
    async def get_server_info() -> str:
        return json.dumps({
            "server": "Verify MCP Server",
            "version": "2.0.0",
            "mcp_protocol": "2025-11-25",
            "features": {
                "tools": 4,
                "prompts": 6,
                "resources": 4,
                "completions": True,
                "progress_notifications": True,
                "logging": True,
                "tool_annotations": True,
            },
            "api_surface": {
                "total_endpoints": discovery.total_endpoints,
                "total_categories": len(discovery.categories),
            },
            "tenant": config.tenant or "(not configured)",
        }, indent=2)

    # ── Resource 4: Tenant Info ─────────────────────────────────────

    @mcp.resource(
        "verify://tenant",
        name="verify_tenant",
        title="Verify Tenant",
        description="IBM Security Verify tenant connection details and status.",
        mime_type="application/json",
    )
    async def get_tenant() -> str:
        return json.dumps({
            "tenant_url": config.tenant or "(not configured)",
            "token_url": config.token_url if config.tenant else "(not configured)",
            "ssl_verification": config.verify_ssl,
            "configured": bool(config.tenant and config.api_client_id),
        }, indent=2)
