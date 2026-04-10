#!/usr/bin/env python3
"""WXO entry point for Verify MCP Server (stdio mode).

Maps WXO_CONNECTION_verify_creds_* environment variables to the bare names
expected by the Verify MCP Server config:
    WXO_CONNECTION_verify_creds_VERIFY_TENANT  ->  VERIFY_TENANT
    WXO_CONNECTION_verify_creds_API_CLIENT_ID  ->  API_CLIENT_ID
    WXO_CONNECTION_verify_creds_API_CLIENT_SECRET  ->  API_CLIENT_SECRET
"""
import os

PREFIX = "WXO_CONNECTION_verify_creds_"
for key, value in os.environ.items():
    if key.startswith(PREFIX):
        bare = key[len(PREFIX):]
        os.environ[bare] = value

# Force stdio transport
os.environ["MCP_TRANSPORT"] = "stdio"

from src.server import main
main()
