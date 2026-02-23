# Verify MCP Server — Dual Mode Container (stdio + HTTP/SSE)
FROM python:3.12-slim

LABEL org.opencontainers.image.source=https://github.com/IBM/verify-mcp-server
LABEL org.opencontainers.image.description="Verify MCP Server — AI-driven access to all IBM Security Verify REST APIs"

WORKDIR /app

# Install dependencies first (cache layer)
COPY pyproject.toml ./
RUN pip install --no-cache-dir .

# Copy source code
COPY src/ ./src/

# Pre-define environment variables (users must set values at runtime via -e)
ENV VERIFY_TENANT="" \
    API_CLIENT_ID="" \
    VERIFY_SSL="true"
# Note: API_CLIENT_SECRET passed at runtime via -e (not baked into image)

# Persistent volume for API key store (/data/keys.json)
VOLUME /data

# Expose HTTP port (used in SSE mode)
EXPOSE 8004

# Default: stdio mode (for Claude Desktop / VS Code)
# Use: --transport sse --host 0.0.0.0 --port 8004 for HTTP/SSE mode
ENTRYPOINT ["python", "-m", "src"]
