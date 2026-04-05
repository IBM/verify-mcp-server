"""Configuration management for Verify MCP Server."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


def _load_env() -> None:
    """Load .env from project root."""
    project_root = Path(__file__).resolve().parents[1]
    load_dotenv(project_root / ".env")


_load_env()


@dataclass(frozen=True)
class VerifyConfig:
    """IBM Security Verify connection configuration from environment variables."""

    tenant: str = field(
        default_factory=lambda: os.getenv("VERIFY_TENANT", "").rstrip("/")
    )
    api_client_id: str = field(
        default_factory=lambda: os.getenv("API_CLIENT_ID", "")
    )
    api_client_secret: str = field(
        default_factory=lambda: os.getenv("API_CLIENT_SECRET", "")
    )
    oidc_client_id: str = field(
        default_factory=lambda: os.getenv("OIDC_CLIENT_ID", "")
    )
    oidc_client_secret: str = field(
        default_factory=lambda: os.getenv("OIDC_CLIENT_SECRET", "")
    )
    verify_ssl: bool = field(
        default_factory=lambda: os.getenv("VERIFY_SSL", "true").lower() == "true"
    )

    @property
    def base_url(self) -> str:
        """Base URL for Verify API calls (tenant root)."""
        return self.tenant

    @property
    def token_url(self) -> str:
        """OAuth2 token endpoint for client_credentials grant."""
        return f"{self.tenant}/v1.0/endpoint/default/token"
