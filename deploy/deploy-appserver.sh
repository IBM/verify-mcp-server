#!/usr/bin/env bash
# deploy-appserver.sh
# Run this script ON appserver1.fyre.ibm.com (9.30.147.112) as root
# Usage: scp deploy-appserver.sh root@9.30.147.112:/tmp/ && ssh root@9.30.147.112 bash /tmp/deploy-appserver.sh

set -euo pipefail

IMAGE="ghcr.io/ibm/verify-mcp-server:latest"
CONTAINER="verify-mcp-server"
PORT=8004

# ── Env (fill in real values or copy from your .env) ─────────────────────────
VERIFY_TENANT="${VERIFY_TENANT:-https://security-squad-gsilab.verify.ibm.com}"
API_CLIENT_ID="${API_CLIENT_ID:-165b94c5-9504-4e02-bd5f-5cfdcab0c1cd}"
API_CLIENT_SECRET="${API_CLIENT_SECRET:-nNMTHEd0i4}"
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
  -v verify-mcp-data:/data \
  -e VERIFY_TENANT="$VERIFY_TENANT" \
  -e API_CLIENT_ID="$API_CLIENT_ID" \
  -e API_CLIENT_SECRET="$API_CLIENT_SECRET" \
  -e VERIFY_SSL="$VERIFY_SSL" \
  -e MCP_TRANSPORT=sse \
  -e MCP_PORT="${PORT}" \
  "$IMAGE"

echo "==> Waiting for startup…"
sleep 4

echo "==> Health check"
curl -sf --max-time 5 http://localhost:${PORT}/health -o /dev/null && \
  echo "✅ Verify MCP Server is UP at http://$(hostname -I | awk '{print $1}'):${PORT}/sse" || \
  echo "❌ Health check failed — check: docker logs $CONTAINER"

echo ""
echo "==> To generate an API key (required for MCP client auth):"
echo "    docker exec -it $CONTAINER curl -s -X POST http://localhost:${PORT}/admin/keys -H 'Content-Type: application/json' -d '{\"user\":\"admin@ibm.com\"}'"
echo ""
echo "==> To list keys:  docker exec -it $CONTAINER curl -s http://localhost:${PORT}/admin/keys"
echo "==> To revoke key: docker exec -it $CONTAINER curl -s -X DELETE http://localhost:${PORT}/admin/keys/<PREFIX>"
