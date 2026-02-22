"""IBM Security Verify REST API HTTP client with automatic Bearer-token injection."""

import logging
from typing import Any

import httpx

from .auth import VerifyAuth
from .config import VerifyConfig

logger = logging.getLogger(__name__)


class VerifyClient:
    """Executes HTTP requests against the IBM Security Verify REST API."""

    def __init__(self, config: VerifyConfig, auth: VerifyAuth) -> None:
        self._config = config
        self._auth = auth

    async def request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        content_type: str = "application/json",
    ) -> dict[str, Any] | list | str:
        """Make an authenticated request to the Verify API.

        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE)
            endpoint: API path (e.g., "/v2.0/Users")
            params: Query string parameters (used for GET, optional for others)
            body: JSON body (used for POST, PUT, PATCH)
            headers: Additional headers to merge
            content_type: Request content type
        """
        token = await self._auth.get_token()
        url = f"{self._config.base_url}{endpoint}"

        # SCIM endpoints require application/scim+json for both Content-Type and Accept
        _scim_paths = ("/v2.0/Users", "/v2.0/Groups", "/v2.0/Me", "/v2.0/Bulk")
        is_scim = any(p in endpoint for p in _scim_paths)
        accept = "application/scim+json" if is_scim else "application/json"

        req_headers = {
            "Authorization": f"Bearer {token}",
            "Accept": accept,
        }
        if content_type:
            req_headers["Content-Type"] = content_type
        elif is_scim and method.upper() in ("POST", "PUT", "PATCH"):
            req_headers["Content-Type"] = "application/scim+json"
        if headers:
            req_headers.update(headers)

        logger.debug("%s %s params=%s body=%s", method.upper(), url, params, body)

        async with httpx.AsyncClient(
            verify=self._config.verify_ssl, timeout=120.0
        ) as http:
            resp = await self._do_request(
                http, method, url, params, body, req_headers
            )

            # Retry once on 401 (token may have expired server-side)
            if resp.status_code == 401:
                logger.info("Got 401, refreshing token and retrying")
                self._auth.invalidate()
                token = await self._auth.get_token()
                req_headers["Authorization"] = f"Bearer {token}"
                resp = await self._do_request(
                    http, method, url, params, body, req_headers
                )

            if self._is_verify_login_html(resp):
                return {
                    "status": "error",
                    "error_code": "AUTH_REDIRECT_DETECTED",
                    "http_code": resp.status_code,
                    "message": "Verify returned an interactive login HTML page instead of API JSON.",
                    "hint": "Token may lack scope/permission for this endpoint or session/auth context is invalid.",
                }

            resp.raise_for_status()

            if resp.status_code == 204 or not resp.content:
                return {"status": "success", "http_code": resp.status_code}

            # Handle SCIM responses (application/scim+json)
            try:
                return resp.json()
            except ValueError:
                return {
                    "status": "success",
                    "http_code": resp.status_code,
                    "body": resp.text[:2000],
                }

    @staticmethod
    async def _do_request(
        http: httpx.AsyncClient,
        method: str,
        url: str,
        params: dict | None,
        body: dict | None,
        headers: dict,
    ) -> httpx.Response:
        """Execute a single HTTP request."""
        method_upper = method.upper()
        if method_upper == "GET":
            return await http.request(method_upper, url, params=params, headers=headers)
        elif body is not None:
            return await http.request(
                method_upper, url, params=params, json=body, headers=headers
            )
        else:
            return await http.request(
                method_upper, url, params=params, headers=headers
            )

    @staticmethod
    def _is_verify_login_html(resp: httpx.Response) -> bool:
        """Detect Verify interactive login HTML returned to API calls."""
        content_type = (resp.headers.get("content-type") or "").lower()
        if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
            return False

        body = resp.text[:4000].lower()
        login_markers = (
            "<html",
            "/idaas/mtfim/sps/idaas/login",
            "runtime=true",
            "location.href",
        )
        return all(marker in body for marker in login_markers)
