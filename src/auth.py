"""OAuth2 client_credentials token management for IBM Security Verify."""

import logging
import time

import httpx

from .config import VerifyConfig

logger = logging.getLogger(__name__)


class VerifyAuth:
    """Acquires and caches OAuth2 tokens using the client_credentials grant."""

    def __init__(self, config: VerifyConfig) -> None:
        self._config = config
        self._token: str | None = None
        self._expires_at: float = 0

    async def get_token(self) -> str:
        """Return a valid Bearer token, refreshing if near expiry."""
        if self._token and time.time() < self._expires_at:
            return self._token
        return await self._acquire_token()

    async def _acquire_token(self) -> str:
        """Request a new token from the Verify OAuth2 endpoint."""
        logger.info("Requesting OAuth2 token from %s", self._config.token_url)
        async with httpx.AsyncClient(
            verify=self._config.verify_ssl, timeout=30.0
        ) as http:
            resp = await http.post(
                self._config.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._config.api_client_id,
                    "client_secret": self._config.api_client_secret,
                    "scope": "openid",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            data = resp.json()

        expires_in = data.get("expires_in", 3600)
        self._token = data["access_token"]
        self._expires_at = time.time() + expires_in - 30  # refresh 30s early
        logger.info("OAuth2 token acquired (expires in %ds)", expires_in)
        return self._token

    def invalidate(self) -> None:
        """Force token refresh on next call."""
        self._token = None
        self._expires_at = 0
