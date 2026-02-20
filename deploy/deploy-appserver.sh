#!/usr/bin/env bash
# deploy-appserver.sh
# Run this script ON appserver1.fyre.ibm.com (9.30.147.112) as root
# Usage: scp deploy-appserver.sh root@9.30.147.112:/tmp/ && ssh root@9.30.147.112 bash /tmp/deploy-appserver.sh

set -euo pipefail

IMAGE="ghcr.io/anujshrivastava15/verify-mcp-server:latest"
CONTAINER="verify-mcp"
PORT=8004

# ── Env (fill in real values or copy from your .env) ─────────────────────────
VERIFY_TENANT="${VERIFY_TENANT:-https://security-squad-gsilab.verify.ibm.com}"
API_CLIENT_ID="${API_CLIENT_ID:-f61d84b1-4d03-4f4b-b328-cb0f735f311a}"
API_CLIENT_SECRET="${API_CLIENT_SECRET:-c2nJBgSxVV}"
VERIFY_SSL="${VERIFY_SSL:-true}"

echo "==> Pulling $IMAGE"
docker pull "$IMAGE"

echo "==> Stopping old container (if any)"
docker rm -f "$CONTAINER" 2>/dev/null || true

echo "==> Starting $CONTAINER on port $PORT"
docker run -d \
  --name "$CONTAINER" \
  --restart unless-stopped \
  -p "${PORT}:${PORT}" \
  -e VERIFY_TENANT="$VERIFY_TENANT" \
  -e API_CLIENT_ID="$API_CLIENT_ID" \
  -e API_CLIENT_SECRET="$API_CLIENT_SECRET" \
  -e VERIFY_SSL="$VERIFY_SSL" \
  -e MCP_TRANSPORT=sse \
  "$IMAGE"

echo "==> Waiting for startup…"
sleep 4

echo "==> Health check"
curl -sf --max-time 5 http://localhost:${PORT}/sse -o /dev/null && \
  echo "✅ Verify MCP Server is UP at http://$(hostname -I | awk '{print $1}'):${PORT}/sse" || \
  echo "❌ Health check failed — check: docker logs $CONTAINER"
