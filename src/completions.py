"""MCP Auto-completions for IBM Security Verify tool arguments.

Provides type-ahead suggestions for:
  - endpoint_id  — all 210+ endpoint identifiers
  - category     — all 89 category names
  - method       — HTTP methods (GET, POST, PUT, PATCH, DELETE)
  - query        — same as endpoint_id (for discover tool)
  - framework    — compliance frameworks (for consent_compliance_report prompt)
  - sso_protocol — SSO protocols (for application_onboarding_guide prompt)
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.types import (
    Completion,
    CompletionArgument,
    CompletionContext,
    PromptReference,
    ResourceTemplateReference,
)

from .discovery import VerifyDiscovery


# Static completion values
_HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
_COMPLIANCE_FRAMEWORKS = ["GDPR", "CCPA", "HIPAA", "SOX", "PCI-DSS", "ISO-27001", "NIST", "SOC2"]
_SSO_PROTOCOLS = ["OIDC", "SAML", "WS-Federation"]

# Tools/prompts that accept endpoint_id or query (same completions)
_ENDPOINT_ID_ARGS = {
    ("verify_discover", "query"),
    ("verify_get_api_details", "endpoint_id"),
    ("verify_execute", "endpoint_id"),
}


def register_completions(mcp: FastMCP, discovery: VerifyDiscovery) -> None:
    """Register a single completion handler for all tool and prompt arguments."""

    all_endpoint_ids = sorted(discovery.endpoints.keys())
    all_categories = sorted(discovery.categories.keys())

    @mcp.completion()
    async def handle_completion(
        ref: PromptReference | ResourceTemplateReference,
        argument: CompletionArgument,
        context: CompletionContext | None = None,
    ) -> Completion | None:
        name = ref.name
        arg = argument.name
        partial = argument.value or ""

        # endpoint_id / query completions
        if (name, arg) in _ENDPOINT_ID_ARGS:
            p = partial.lower()
            if not p:
                matches = all_endpoint_ids[:50]
            else:
                matches = [eid for eid in all_endpoint_ids if p in eid.lower()][:50]
            return Completion(values=matches, total=len(all_endpoint_ids), hasMore=len(matches) < len(all_endpoint_ids))

        # category completions
        if name == "verify_discover" and arg == "category":
            p = partial.lower()
            if not p:
                matches = all_categories
            else:
                matches = [c for c in all_categories if p in c.lower()]
            return Completion(values=matches, total=len(all_categories), hasMore=False)

        # method completions
        if name == "verify_discover" and arg == "method":
            p = partial.upper()
            if not p:
                matches = _HTTP_METHODS
            else:
                matches = [m for m in _HTTP_METHODS if m.startswith(p)]
            return Completion(values=matches, total=len(_HTTP_METHODS), hasMore=False)

        # prompt: consent_compliance_report → framework
        if name == "consent_compliance_report" and arg == "framework":
            p = partial.upper()
            if not p:
                matches = _COMPLIANCE_FRAMEWORKS
            else:
                matches = [f for f in _COMPLIANCE_FRAMEWORKS if f.upper().startswith(p)]
            return Completion(values=matches, total=len(_COMPLIANCE_FRAMEWORKS), hasMore=False)

        # prompt: application_onboarding_guide → sso_protocol
        if name == "application_onboarding_guide" and arg == "sso_protocol":
            p = partial.upper()
            if not p:
                matches = _SSO_PROTOCOLS
            else:
                matches = [pr for pr in _SSO_PROTOCOLS if pr.upper().startswith(p)]
            return Completion(values=matches, total=len(_SSO_PROTOCOLS), hasMore=False)

        return None
