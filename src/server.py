"""IBM Security Verify MCP Server."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from .auth import VerifyAuth
from .client import VerifyClient
from .config import VerifyConfig
from .discovery import VerifyDiscovery
from .keystore import KeyStore
from .tools import register_tools

logger = logging.getLogger(__name__)

# Server metadata
SERVER_NAME = "Verify MCP Server"
SERVER_VERSION = "1.0.0"
SSE_HOST = "0.0.0.0"
SSE_PORT = int(os.getenv("MCP_PORT", "8004"))

# Instructions shown to the LLM at the start of a session
SERVER_INSTRUCTIONS = "IBM Security Verify MCP Server."

# ── Singleton key store (initialised once, shared by middleware + admin) ──
_key_store: KeyStore | None = None


def _get_key_store() -> KeyStore:
    """Return (and lazily create) the global KeyStore singleton."""
    global _key_store
    if _key_store is None:
        _key_store = KeyStore()
    return _key_store


# ═══════════════════════════════════════════════════════════════════════
#  API-Key Authentication Middleware (Starlette)
# ═══════════════════════════════════════════════════════════════════════

class APIKeyMiddleware(BaseHTTPMiddleware):
    """Require a valid API key in the Authorization header for /sse.

    Public (unauthenticated) routes:
        /health            — liveness probe
        /admin/keys        — admin key management (localhost-only)

    Protected routes:
        /sse               — MCP SSE transport (requires valid API key)
        /messages          — MCP message posting (requires valid API key)
    """

    OPEN_PREFIXES = ("/health", "/admin/keys")

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Allow public endpoints through without auth
        if any(path.startswith(prefix) for prefix in self.OPEN_PREFIXES):
            return await call_next(request)

        # Everything else requires a valid API key
        ks = _get_key_store()

        # If no keys have been generated yet, allow open access
        # (first-run experience — admin should generate a key immediately)
        if not ks.has_any_keys():
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header:
            return JSONResponse(
                {"error": "Authorization header required"},
                status_code=401,
            )

        # Accept "Bearer <key>" or raw "<key>"
        raw_key = auth_header.removeprefix("Bearer ").strip()
        if not raw_key:
            return JSONResponse(
                {"error": "Authorization header required"},
                status_code=401,
            )

        if not ks.validate(raw_key):
            return JSONResponse(
                {"error": "Invalid API key"},
                status_code=401,
            )

        return await call_next(request)


# ═══════════════════════════════════════════════════════════════════════
#  Admin Endpoints (localhost-only)
# ═══════════════════════════════════════════════════════════════════════

def _is_localhost(request: Request) -> bool:
    """Return True if the request originates from localhost."""
    client = request.client
    if client is None:
        return False
    return client.host in ("127.0.0.1", "::1", "localhost")


async def admin_create_key(request: Request) -> JSONResponse:
    """POST /admin/keys — Generate a new API key (localhost-only)."""
    if not _is_localhost(request):
        return JSONResponse({"error": "Admin endpoints are localhost-only"}, status_code=403)
    try:
        data = await request.json()
        user = data.get("user", "anonymous")
    except Exception:
        user = "anonymous"

    ks = _get_key_store()
    raw_key = ks.generate(user)
    return JSONResponse({
        "api_key": raw_key,
        "prefix": raw_key[:8],
        "user": user,
        "message": "Store this key securely — it will not be shown again.",
    })


async def admin_list_keys(request: Request) -> JSONResponse:
    """GET /admin/keys — List all API keys (prefixes only, localhost-only)."""
    if not _is_localhost(request):
        return JSONResponse({"error": "Admin endpoints are localhost-only"}, status_code=403)
    ks = _get_key_store()
    return JSONResponse({"keys": ks.list_keys()})


async def admin_revoke_key(request: Request) -> JSONResponse:
    """DELETE /admin/keys/{prefix} — Revoke an API key (localhost-only)."""
    if not _is_localhost(request):
        return JSONResponse({"error": "Admin endpoints are localhost-only"}, status_code=403)
    prefix = request.path_params["prefix"]
    ks = _get_key_store()
    if ks.revoke(prefix):
        return JSONResponse({"message": f"Key {prefix}… revoked"})
    return JSONResponse({"error": f"No key with prefix {prefix}"}, status_code=404)


async def health(request: Request) -> JSONResponse:
    """GET /health — Liveness probe (always public)."""
    ks = _get_key_store()
    return JSONResponse({
        "status": "healthy",
        "server": SERVER_NAME,
        "version": SERVER_VERSION,
        "auth_enabled": ks.has_any_keys(),
    })


# ═══════════════════════════════════════════════════════════════════════
#  Server Creation
# ═══════════════════════════════════════════════════════════════════════

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
        import uvicorn

        # Build the SSE ASGI app from FastMCP
        sse_app = mcp.sse_app()

        # Compose Starlette app: admin routes + health + MCP SSE transport
        app = Starlette(
            routes=[
                Route("/health", health, methods=["GET"]),
                Route("/admin/keys", admin_create_key, methods=["POST"]),
                Route("/admin/keys", admin_list_keys, methods=["GET"]),
                Route("/admin/keys/{prefix}", admin_revoke_key, methods=["DELETE"]),
                # Mount the MCP SSE transport under /
                Mount("/", app=sse_app),
            ],
            middleware=[Middleware(APIKeyMiddleware)],
        )

        ks = _get_key_store()
        if ks.has_any_keys():
            logger.info("API key authentication ENABLED (%d key(s) loaded)", len(ks.list_keys()))
        else:
            logger.warning(
                "No API keys configured — SSE endpoint is OPEN. "
                "Generate a key: curl -X POST http://localhost:%d/admin/keys -H 'Content-Type: application/json' -d '{\"user\":\"admin@ibm.com\"}'",
                SSE_PORT,
            )

        logger.info("SSE server listening on %s:%d", SSE_HOST, SSE_PORT)
        uvicorn.run(app, host=SSE_HOST, port=SSE_PORT, log_level=log_level.lower())
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
