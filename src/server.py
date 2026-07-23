"""IBM Security Verify MCP Server — v2.0.

V2 additions over v1:
  - Streamable HTTP transport (MCP 2025-11-25)
  - MCP Resources (4), Prompts (6), Completions
  - Tool annotations (readOnlyHint, destructiveHint, etc.)
  - Progress notifications + MCP logging
  - TLS support (self-signed or custom certs)
  - Stateless HTTP for scalable deployments
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import sys
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from .auth import VerifyAuth
from .client import VerifyClient
from .completions import register_completions
from .config import VerifyConfig
from .discovery import VerifyDiscovery
from .keystore import KeyStore
from .prompts import register_prompts
from .resources import register_resources
from .tools import register_tools

logger = logging.getLogger(__name__)

# Server metadata
SERVER_NAME = "Verify MCP Server"
SERVER_VERSION = "2.0.0"
# Default to loopback. Set MCP_HOST=0.0.0.0 explicitly for container publish.
SSE_HOST = os.getenv("MCP_HOST", "127.0.0.1")
SSE_PORT = int(os.getenv("MCP_PORT", "8004"))

# Instructions shown to the LLM at the start of a session
SERVER_INSTRUCTIONS = (
    "IBM Security Verify MCP Server. "
    "Provides access to 210+ IBM Security Verify API endpoints for identity, "
    "access, MFA, federation, consent, and governance management. "
    "Workflow: verify_discover → verify_get_api_details → verify_execute. "
    "Use verify_list_categories to browse the full API surface."
)

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
    """Require a valid API key for MCP HTTP routes.

    Public:
        /health — liveness probe

    Admin (MCP_ADMIN_TOKEN, not API keystore):
        /admin/keys — skipped here; handlers enforce admin token

    Protected:
        /sse, /messages, and other MCP routes — require a keystore API key

    Fail-closed: if the keystore is empty, MCP routes return 503 (no open first-run).
    """

    OPEN_PREFIXES = ("/health",)
    ADMIN_PREFIXES = ("/admin/keys",)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if any(path.startswith(prefix) for prefix in self.OPEN_PREFIXES):
            return await call_next(request)

        # Admin routes use MCP_ADMIN_TOKEN (checked in handlers), not keystore keys
        if any(path.startswith(prefix) for prefix in self.ADMIN_PREFIXES):
            return await call_next(request)

        ks = _get_key_store()

        if not ks.has_any_keys():
            return JSONResponse(
                {
                    "error": (
                        "No API keys configured. Set MCP_ADMIN_TOKEN and POST /admin/keys "
                        "to create a key before using MCP HTTP transports."
                    ),
                },
                status_code=503,
            )

        auth_header = request.headers.get("Authorization", "")
        if not auth_header:
            return JSONResponse(
                {"error": "Authorization header required"},
                status_code=401,
            )

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
#  Admin Endpoints (MCP_ADMIN_TOKEN required — not IP-based trust)
# ═══════════════════════════════════════════════════════════════════════

def _admin_authorized(request: Request) -> bool:
    """Return True when request presents a valid MCP_ADMIN_TOKEN.

    Does not trust request.client.host (broken behind reverse proxies).
    """
    admin_token = os.getenv("MCP_ADMIN_TOKEN", "").strip()
    if not admin_token:
        return False

    candidates: list[str] = []
    auth_header = request.headers.get("Authorization", "")
    if auth_header:
        candidates.append(auth_header.removeprefix("Bearer ").strip())
    x_admin = request.headers.get("X-Admin-Token", "").strip()
    if x_admin:
        candidates.append(x_admin)

    for candidate in candidates:
        if candidate and secrets.compare_digest(candidate, admin_token):
            return True
    return False


def _admin_forbidden() -> JSONResponse:
    return JSONResponse(
        {
            "error": (
                "Admin endpoints require MCP_ADMIN_TOKEN "
                "(Authorization: Bearer <token> or X-Admin-Token header)."
            ),
        },
        status_code=403,
    )


async def admin_create_key(request: Request) -> JSONResponse:
    """POST /admin/keys — Generate a new API key (admin token required)."""
    if not _admin_authorized(request):
        return _admin_forbidden()
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
    """GET /admin/keys — List all API keys (prefixes only, admin token required)."""
    if not _admin_authorized(request):
        return _admin_forbidden()
    ks = _get_key_store()
    return JSONResponse({"keys": ks.list_keys()})


async def admin_revoke_key(request: Request) -> JSONResponse:
    """DELETE /admin/keys/{prefix} — Revoke an API key (admin token required)."""
    if not _admin_authorized(request):
        return _admin_forbidden()
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
        "keys_configured": ks.has_any_keys(),
        "admin_token_configured": bool(os.getenv("MCP_ADMIN_TOKEN", "").strip()),
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

    transport = os.getenv("MCP_TRANSPORT", "stdio").lower()

    # Create FastMCP server with v2 capabilities
    mcp_kwargs: dict = {
        "instructions": SERVER_INSTRUCTIONS,
        "host": SSE_HOST,
        "port": SSE_PORT,
    }
    # Enable stateless HTTP for streamable-http transport
    if transport == "streamable-http":
        mcp_kwargs["stateless_http"] = True

    mcp = FastMCP(SERVER_NAME, **mcp_kwargs)

    # Register v2 components: tools, prompts, resources, completions
    register_tools(mcp, client, discovery)
    register_prompts(mcp)
    register_resources(mcp, config, discovery)
    register_completions(mcp, discovery)
    logger.info(
        "Registered: 4 tools, 6 prompts, 4 resources, completions enabled"
    )

    return mcp, client


def main() -> None:
    """Entry point — run the MCP server in stdio, SSE, or streamable-http mode."""
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

    if transport in ("sse", "streamable-http"):
        import uvicorn

        # Build the appropriate ASGI app from FastMCP
        if transport == "streamable-http":
            mcp_app = mcp.streamable_http_app()
        else:
            mcp_app = mcp.sse_app()

        # Lifespan: initialise the MCP session manager's task group
        # so streamable-http requests don't fail with "Task group not initialized".
        # session_manager is only available after streamable_http_app() — skip for SSE.
        @asynccontextmanager
        async def lifespan(app):
            if transport == "streamable-http":
                async with mcp.session_manager.run():
                    logger.info("MCP session manager started")
                    yield
            else:
                yield

        # Compose Starlette app: admin routes + health + MCP transport
        app = Starlette(
            routes=[
                Route("/health", health, methods=["GET"]),
                Route("/admin/keys", admin_create_key, methods=["POST"]),
                Route("/admin/keys", admin_list_keys, methods=["GET"]),
                Route("/admin/keys/{prefix}", admin_revoke_key, methods=["DELETE"]),
                # Mount the MCP transport under /
                Mount("/", app=mcp_app),
            ],
            middleware=[Middleware(APIKeyMiddleware)],
            lifespan=lifespan,
        )

        ks = _get_key_store()
        admin_set = bool(os.getenv("MCP_ADMIN_TOKEN", "").strip())
        if ks.has_any_keys():
            logger.info("API key authentication ENABLED (%d key(s) loaded)", len(ks.list_keys()))
        else:
            logger.warning(
                "No API keys configured — MCP HTTP routes return 503 until you create a key. "
                "Set MCP_ADMIN_TOKEN, then: curl -X POST http://127.0.0.1:%d/admin/keys "
                "-H 'Authorization: Bearer $MCP_ADMIN_TOKEN' "
                "-H 'Content-Type: application/json' -d '{\"user\":\"admin@in.ibm.com\"}'",
                SSE_PORT,
            )
        if not admin_set:
            logger.warning(
                "MCP_ADMIN_TOKEN is not set — /admin/keys will reject all admin requests"
            )

        # TLS support
        ssl_kwargs: dict = {}
        ssl_certfile = os.getenv("MCP_SSL_CERTFILE")
        ssl_keyfile = os.getenv("MCP_SSL_KEYFILE")
        if ssl_certfile and ssl_keyfile:
            ssl_kwargs["ssl_certfile"] = ssl_certfile
            ssl_kwargs["ssl_keyfile"] = ssl_keyfile
            logger.info("TLS enabled (custom certs)")
        elif os.getenv("MCP_SSL_SELF_SIGNED", "false").lower() == "true":
            cert, key = _generate_self_signed_cert()
            ssl_kwargs["ssl_certfile"] = cert
            ssl_kwargs["ssl_keyfile"] = key
            logger.info("TLS enabled (self-signed)")

        logger.info(
            "%s server listening on %s:%d",
            transport.upper(),
            SSE_HOST,
            SSE_PORT,
        )
        uvicorn.run(
            app,
            host=SSE_HOST,
            port=SSE_PORT,
            log_level=log_level.lower(),
            **ssl_kwargs,
        )
    else:
        mcp.run(transport="stdio")


def _generate_self_signed_cert() -> tuple[str, str]:
    """Generate a self-signed TLS certificate for development use."""
    import subprocess
    import tempfile

    cert_dir = tempfile.mkdtemp(prefix="verify-mcp-")
    cert_path = os.path.join(cert_dir, "cert.pem")
    key_path = os.path.join(cert_dir, "key.pem")

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "365", "-nodes",
            "-subj", "/CN=verify-mcp-server",
        ],
        check=True,
        capture_output=True,
    )
    logger.info("Self-signed cert generated: %s", cert_path)
    return cert_path, key_path


if __name__ == "__main__":
    main()
