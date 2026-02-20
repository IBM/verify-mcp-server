# Verify MCP Server

**Model Context Protocol (MCP) server for IBM Security Verify** — Access 200+ IBM Verify REST API endpoints through just 4 intelligent MCP tools.

---

## What is This?

Verify MCP Server bridges **Large Language Models (LLMs)** and **IBM Security Verify (IDaaS)**. Instead of exposing 200+ API endpoints as separate tools (which would overwhelm any LLM context window), this server consolidates them into **4 intelligent tools** — achieving a **98% reduction** in token usage.

| Traditional Approach | Verify MCP Server |
|---------------------|-------------------|
| 200+ tool definitions | **4 tool definitions** |
| ~50,000 tokens/request | **~2,000 tokens/request** |
| Context overflow risk | Fits any LLM context |

Works with any MCP-compatible client: VS Code Copilot, Claude Desktop, custom AI agents, or direct HTTP calls.

---

## Quick Start

### Prerequisites

- **Docker** or **Podman** installed
- **IBM Security Verify tenant** with API access
- **API Client credentials** — create an API client in your Verify admin console with appropriate entitlements

### Step 1: Pull the Container

```bash
docker pull ghcr.io/anujshrivastava15/verify-mcp-server:latest
```

> Multi-arch image — works on Intel/AMD (x86_64) and Apple Silicon/ARM (aarch64).

### Step 2: Run the Container

```bash
docker run -d \
  --name verify-mcp \
  -p 8004:8004 \
  -e VERIFY_TENANT="https://your-tenant.verify.ibm.com" \
  -e API_CLIENT_ID="your-api-client-id" \
  -e API_CLIENT_SECRET="your-api-client-secret" \
  ghcr.io/anujshrivastava15/verify-mcp-server:latest
```

Replace:

- `your-tenant.verify.ibm.com` with your IBM Verify tenant URL
- `your-api-client-id` and `your-api-client-secret` with your API client credentials

### Step 3: Verify

```bash
curl http://localhost:8004/health
```

Expected response:

```json
{"status": "healthy", "mode": "http", "tools": 4, "categories": 83, "endpoints": 200}
```

That's it — the MCP server is running and ready to use.

---

## Using the MCP Server

### Available Tools

| Tool | Description | Use For |
|------|-------------|---------|
| `verify_discover` | Search endpoints by keyword or category | Find the right API for users, groups, MFA, policies |
| `verify_list_categories` | List all 83 API categories with endpoint counts | Browse the full API surface |
| `verify_get_api_details` | Get full parameter schema for a specific endpoint | Understand required params before calling |
| `verify_execute` | Execute any Verify API endpoint | GET, POST, PUT, PATCH, DELETE any resource |

### The 3-Step LLM Workflow

The LLM follows a **discover → inspect → execute** pattern:

```
1. verify_discover("users")           → finds user-related endpoints
2. verify_get_api_details("getUsers") → gets params, body schema, auth requirements
3. verify_execute("GET", "/v2.0/Users") → returns actual user data
```

After the first discovery, the LLM **learns the pattern** and stops calling discover — further reducing tokens in multi-turn conversations.

### HTTP API Examples

**Discover endpoints:**

```bash
curl -X POST http://localhost:8004/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "verify_discover",
    "arguments": {"search": "users"}
  }'
```

**List all API categories:**

```bash
curl -X POST http://localhost:8004/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "verify_list_categories",
    "arguments": {}
  }'
```

**Get endpoint details:**

```bash
curl -X POST http://localhost:8004/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "verify_get_api_details",
    "arguments": {"endpoint_id": "getUsers"}
  }'
```

**Execute an API call:**

```bash
curl -X POST http://localhost:8004/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "verify_execute",
    "arguments": {
      "method": "GET",
      "endpoint": "/v2.0/Users",
      "params": {"count": 10}
    }
  }'
```

**List all tools:**

```bash
curl http://localhost:8004/tools
```

### With VS Code Copilot (SSE Mode)

Add to `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "verify": {
      "type": "sse",
      "url": "http://localhost:8004/sse"
    }
  }
}
```

### With Claude Desktop (stdio Mode)

Add to your Claude Desktop MCP config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "verify": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "VERIFY_TENANT=https://your-tenant.verify.ibm.com",
        "-e", "API_CLIENT_ID=your-api-client-id",
        "-e", "API_CLIENT_SECRET=your-api-client-secret",
        "ghcr.io/anujshrivastava15/verify-mcp-server:latest",
        "--stdio"
      ]
    }
  }
}
```

Then ask things like:

- *"List all users in my Verify tenant"*
- *"Show me all MFA enrollment methods for user X"*
- *"What access policies are configured?"*
- *"Check the OIDC federation settings"*
- *"Show me recent audit events"*

---

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VERIFY_TENANT` | Yes | — | Verify tenant URL (e.g., `https://mytenant.verify.ibm.com`) |
| `API_CLIENT_ID` | Yes | — | API client ID for client_credentials grant |
| `API_CLIENT_SECRET` | Yes | — | API client secret |
| `VERIFY_VERIFY_SSL` | No | `true` | Verify SSL certificates |

### Runtime Modes

| Mode | Flag | Use Case |
|------|------|----------|
| HTTP/SSE (default) | `--host 0.0.0.0 --port 8004` | Containers, web clients, direct API |
| stdio | `--stdio` | Claude Desktop, VS Code, local CLI tools |

---

## API Coverage

### 83 API Categories — 200+ Endpoints

The Verify MCP Server covers the **complete** IBM Security Verify REST API surface:

| Domain | Categories | Example Operations |
|--------|-----------|-------------------|
| **Identity Management** | Users (SCIM v2.0), Groups, Dynamic Groups, User Self Care, Identity Sources | List/create/update/delete users, manage group membership, bulk operations |
| **Authentication & MFA** | OIDC, Password Auth, Email OTP, SMS OTP, TOTP, Voice OTP, FIDO2, QR Login, Knowledge Questions, Signature Auth, Authenticators | Enroll factors, verify OTP, manage FIDO registrations, session management |
| **Federation** | SAML 2.0, WS-Federation, OIDC Federation, Social JWT Exchange | Manage federations, aliases, IdP attribute mappings |
| **Access & Policy** | Access Policies v5.0, Application Access, Entitlements, Access Requests, Access Management | Create risk-based policies, manage application access, entitlement assignments |
| **Privacy & Consent (DPCM)** | Data Privacy Management, Consent Records, External Consent Providers, Data Subject Presentation | Create/update consent, manage purposes, data usage approval |
| **Configuration** | API Clients, OIDC Clients, Password Policies, Tenant Properties, Themes, Templates, Adapters, Provisioning | Manage API clients, rotate secrets, configure password policies |
| **MFA Configuration** | Email/SMS/TOTP/Voice OTP Config, FIDO Config, QR Config, Authenticator Clients, Signature Config, reCAPTCHA | Configure MFA methods, set OTP policies |
| **Operations & Monitoring** | Events, Reports, Query Logs, Webhooks, Threat Insights | Query audit logs, export reports, configure webhooks |
| **Governance** | Certification Campaigns v2.0 (configs, instances, assignments, statistics) | Manage access certification campaigns |
| **Other** | Certificates, Push Credentials, Email Suppression, Password Vault, Agent Bridge, Device Manager, Smartcard/X.509, Flow Management | Certificate management, push notification config, flow orchestration |

---

## Build from Source

```bash
git clone https://github.com/IBM/verify-mcp-server.git
cd verify-mcp-server

# Build container
docker build -t verify-mcp-server -f container/Dockerfile .

# Run
docker run -d --name verify-mcp -p 8004:8004 \
  -e VERIFY_TENANT="https://your-tenant.verify.ibm.com" \
  -e API_CLIENT_ID="your-api-client-id" \
  -e API_CLIENT_SECRET="your-api-client-secret" \
  verify-mcp-server
```

---

## Architecture

### How It Works

```mermaid
flowchart TB
    subgraph CLIENT["MCP Client (LLM / VS Code Copilot / Claude Desktop)"]
        U([User Prompt])
    end

    subgraph MCP["Verify MCP Server"]
        direction TB
        T{Router}

        subgraph TOOLS["4 MCP Tools"]
            direction LR
            T1["verify_discover\n─────────────\nSearch 200+ endpoints\nby keyword/category\nvia hardcoded schema"]
            T2["verify_list_categories\n─────────────\nBrowse all 83 API\ncategories with\nendpoint counts"]
            T3["verify_get_api_details\n─────────────\nFull parameter schema\nfor any endpoint\nbefore execution"]
            T4["verify_execute\n─────────────\nGET/POST/PUT/PATCH/DELETE\nAny Verify API\nendpoint"]
        end

        subgraph AUTH["OAuth2 Token Handling"]
            direction LR
            CC["client_credentials Grant\n→ /v1.0/endpoint/default/token\n→ Bearer Token"]
            CACHE["Token Cache\nAuto-refresh before\nexpiry"]
        end

        CC --> CACHE
    end

    subgraph VERIFY["IBM Security Verify (IDaaS)"]
        API["REST API\n200+ Endpoints"]
        subgraph CATEGORIES["API Domains"]
            direction LR
            C1["Identity\nUsers · Groups\nSCIM v2.0"]
            C2["Authentication\nMFA · FIDO2\nOTP · QR"]
            C3["Federation\nSAML · OIDC\nWS-Fed"]
            C4["Access & Policy\nPolicies · Entitlements\nApplications"]
            C5["Privacy\nConsent · DPCM\nPurposes"]
            C6["Operations\nEvents · Logs\nReports"]
        end
    end

    U -->|"HTTP/SSE or stdio"| T
    T --> T1 & T2 & T3 & T4
    T1 & T2 & T3 & T4 -->|"HTTPS + Bearer token"| API
    API --- CATEGORIES
```

### Tool Workflow

```mermaid
sequenceDiagram
    actor User as User / LLM
    participant MCP as MCP Server
    participant Verify as IBM Verify API

    Note over MCP: OAuth2 client_credentials grant
    MCP->>Verify: POST /v1.0/endpoint/default/token
    Verify-->>MCP: Bearer token (cached)

    User->>MCP: verify_discover(search="users")
    MCP-->>User: Matching endpoints with schemas

    User->>MCP: verify_get_api_details(endpoint_id="getUsers")
    MCP-->>User: Full params: count, startIndex, filter, sortBy...

    User->>MCP: verify_execute(method="GET", endpoint="/v2.0/Users", params={count: 10})
    MCP->>Verify: GET /v2.0/Users?count=10 [Bearer token]
    Verify-->>MCP: SCIM user list
    MCP-->>User: JSON results

    User->>MCP: verify_execute(method="POST", endpoint="/v2.0/Users", body={...})
    MCP->>Verify: POST /v2.0/Users [Bearer token]
    Verify-->>MCP: Created user
    MCP-->>User: New user details
```

### Token Efficiency

```mermaid
graph LR
    subgraph NAIVE["❌ Naive: 1 Tool per Endpoint"]
        A["200+ tool definitions\n~50,000 tokens/request\nContext overflow"]
    end

    subgraph META["✅ Meta-Tool Pattern"]
        B["4 tool definitions\n~2,000 tokens/request\n98% reduction"]
    end

    NAIVE -.->|"replaced by"| META
```

In a **10-turn conversation**, this saves approximately **480,000 tokens** compared to the per-endpoint approach.

---

## Support

**Found a bug?**

- Open an issue at [github.com/IBM/verify-mcp-server/issues](https://github.com/IBM/verify-mcp-server/issues)
- Provide: steps to reproduce, environment details, and relevant logs
- Include log snippets: `docker logs verify-mcp`

**Need help?**

- Check container logs: `docker logs verify-mcp`
- Contact: [ashrivastava@in.ibm.com](mailto:ashrivastava@in.ibm.com), [rahul.k.p@ibm.com](mailto:rahul.k.p@ibm.com)

---

## Disclaimer

All content in this repository including code has been provided by IBM under the associated open source software license and IBM is under no obligation to provide enhancements, updates, or support. IBM developers produced this code as an open source project (not as an IBM product), and IBM makes no assertions as to the level of quality nor security, and will not be maintaining this code going forward.
