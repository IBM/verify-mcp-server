"""IBM Security Verify MCP Server — FastMCP bootstrap.

Wires together config, auth, HTTP client, discovery, and tools into a
single MCP server that supports both stdio and SSE transports.

Usage:
  # stdio mode (default — for Claude Desktop / VS Code)
  python -m src

  # SSE mode (HTTP server on port 8004)
  MCP_TRANSPORT=sse python -m src
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

from mcp.server.fastmcp import FastMCP

from .auth import VerifyAuth
from .client import VerifyClient
from .config import VerifyConfig
from .discovery import VerifyDiscovery
from .tools import register_tools

logger = logging.getLogger(__name__)

# Server metadata
SERVER_NAME = "Verify MCP Server"
SERVER_VERSION = "1.0.0"
SSE_HOST = "0.0.0.0"
SSE_PORT = int(os.getenv("MCP_PORT", "8004"))

# Instructions shown to the LLM at the start of a session
SERVER_INSTRUCTIONS = """\
You are connected to the IBM Security Verify MCP Server.

IBM Security Verify is IBM's cloud-native Identity-as-a-Service (IDaaS)
platform covering user lifecycle management, SSO, MFA, adaptive access,
federation, and data privacy & consent.

Available tools:
  1. verify_list_categories — list all API categories and endpoint counts
  2. verify_discover        — search endpoints by keyword / category / method
  3. verify_get_api_details — get parameter schema for a specific endpoint
  4. verify_execute         — execute any Verify API endpoint

Workflow:
  Step 1: Use verify_list_categories or verify_discover to find endpoints
  Step 2: Use verify_get_api_details to understand the parameters
  Step 3: Use verify_execute to call the endpoint

Tips:
  - SCIM endpoints use /v2.0/Users and /v2.0/Groups with SCIM filter syntax
  - Path parameters like {id} are auto-substituted from params
  - Always check verify_get_api_details for required fields before executing
"""


def create_server() -> tuple[FastMCP, VerifyClient]:
    """Create and configure the MCP server instance.

    Returns:
        Tuple of (FastMCP server, VerifyClient) — the client is returned
        so the caller can close it on shutdown.
    """
    # Load configuration from environment / .env
    config = VerifyConfig()
    logger.info("Loaded Verify config for tenant: %s", config.tenant)

    # Create auth, client, and discovery
    auth = VerifyAuth(config)
    client = VerifyClient(config, auth)
    discovery = VerifyDiscovery()

    logger.info(
        "Discovery indexed %d endpoints across %d categories",
        discovery.total_endpoints,
        len(discovery.categories),
    )

    # Create FastMCP server (host/port used for SSE transport)
    mcp = FastMCP(
        SERVER_NAME,
        instructions=SERVER_INSTRUCTIONS,
        host=SSE_HOST,
        port=SSE_PORT,
    )

    # Register the four meta-tools
    register_tools(mcp, client, discovery)
    logger.info("Registered %d MCP tools", 4)

    return mcp, client


def main() -> None:
    """Entry point — run the MCP server in stdio or SSE mode."""
    # Configure logging
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    transport = os.getenv("MCP_TRANSPORT", "stdio").lower()

    mcp, client = create_server()

    logger.info(
        "Starting %s v%s (transport=%s)",
        SERVER_NAME,
        SERVER_VERSION,
        transport,
    )

    if transport == "sse":
        # FastMCP reads host/port from the constructor settings
        logger.info("SSE server listening on %s:%d", SSE_HOST, SSE_PORT)
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
