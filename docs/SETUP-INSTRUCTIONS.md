# IBM Security Verify MCP Server V2 - Setup Instructions

This guide provides step-by-step instructions for setting up and connecting to the IBM Security Verify MCP Server V2.

---

## Prerequisites

### Required
- ✅ Bob AI Assistant (with MCP support)
- ✅ Access to IBM Security Verify tenant
- ✅ API authentication token
- ✅ Network access to MCP server endpoint

### Optional
- 📝 VS Code (for editing configuration files)
- 🔍 Postman or curl (for testing API connectivity)

---

## Step 1: Obtain Server Details

### Server Information
- **Server URL**: `https://9.30.147.112:30804/mcp`
- **Connection Type**: `streamable-http` (HTTPS)
- **Tenant**: `security-squad-gsilab.verify.ibm.com`
- **API Version**: v2.0

### Authentication
You need a Bearer token for authentication. Contact your IBM Security Verify administrator to obtain:
1. API client credentials
2. Bearer token with appropriate scopes

**Required Scopes**:
- `read:users` - Read user information
- `write:users` - Create/update users
- `read:groups` - Read group information
- `read:factors` - Read MFA factor information

---

## Step 2: Configure MCP Server

### Option A: Using Bob's MCP Settings

1. Open Bob's MCP settings file:
   ```
   ~/.bob/settings/mcp_settings.json
   ```

2. Add the Verify MCP Server configuration:
   ```json
   {
     "mcpServers": {
       "verify-mcp-server-v2": {
         "type": "streamable-http",
         "url": "https://9.30.147.112:30804/mcp",
         "headers": {
           "Authorization": "Bearer YOUR_TOKEN_HERE"
         }
       }
     }
   }
   ```

3. Replace `YOUR_TOKEN_HERE` with your actual Bearer token

4. Save the file

### Option B: Using Project-Specific Configuration

1. Create a configuration file in your project:
   ```bash
   mkdir -p verify-mcp-testing
   cd verify-mcp-testing
   ```

2. Create `verify-mcp-server-v2.json`:
   ```json
   {
     "mcpServers": {
       "verify-mcp-server-v2": {
         "type": "streamable-http",
         "url": "https://9.30.147.112:30804/mcp",
         "headers": {
           "Authorization": "Bearer YOUR_TOKEN_HERE"
         }
       }
     }
   }
   ```

3. Replace `YOUR_TOKEN_HERE` with your actual Bearer token

---

## Step 3: Reload Bob

After updating the configuration, reload Bob to apply changes:

1. In VS Code, open Command Palette (Cmd+Shift+P or Ctrl+Shift+P)
2. Type "Reload Window" and select it
3. Wait for Bob to restart

**Alternative**: Restart VS Code completely

---

## Step 4: Verify Connection

### Test 1: List Categories
Ask Bob to list all API categories:

```
List all IBM Security Verify API categories using the verify MCP server
```

**Expected Output**: JSON with 89 categories and 210 endpoints

### Test 2: Search Endpoints
Ask Bob to search for user endpoints:

```
Search for user management endpoints in the verify MCP server
```

**Expected Output**: List of user-related endpoints grouped by category

### Test 3: Execute API Call
Ask Bob to get user details:

```
Using the verify MCP server, get details for user ID 109156235735988319
```

**Expected Output**: User object with name, email, and status

---

## Troubleshooting

### Issue 1: "Server not found" Error

**Symptoms**:
```
Error: MCP server 'verify-mcp-server-v2' not found
```

**Solutions**:
1. ✅ Verify the server name matches exactly in configuration
2. ✅ Reload Bob after configuration changes
3. ✅ Check that the configuration file is in the correct location
4. ✅ Ensure JSON syntax is valid (no trailing commas, proper quotes)

### Issue 2: "401 Unauthorized" Error

**Symptoms**:
```
Error: Client error '401 Unauthorized'
```

**Solutions**:
1. ✅ Verify Bearer token is correct and not expired
2. ✅ Check token has required scopes
3. ✅ Ensure "Bearer " prefix is included in Authorization header
4. ✅ Contact administrator to regenerate token if needed

### Issue 3: "Connection Timeout" Error

**Symptoms**:
```
Error: Connection timeout to https://9.30.147.112:30804/mcp
```

**Solutions**:
1. ✅ Verify network connectivity to server
2. ✅ Check firewall rules allow HTTPS traffic
3. ✅ Confirm VPN connection if required
4. ✅ Test connectivity with curl:
   ```bash
   curl -H "Authorization: Bearer YOUR_TOKEN" \
        https://9.30.147.112:30804/mcp
   ```

### Issue 4: "Tool not found" Error

**Symptoms**:
```
Error: Tool 'verify_discover' does not exist on server
```

**Solutions**:
1. ✅ Verify server is running and accessible
2. ✅ Check server version supports required tools
3. ✅ Reload Bob to refresh server capabilities
4. ✅ Contact server administrator to verify server status

### Issue 5: "Invalid JSON" Error

**Symptoms**:
```
Error: Invalid JSON in configuration file
```

**Solutions**:
1. ✅ Use a JSON validator (e.g., jsonlint.com)
2. ✅ Check for trailing commas (not allowed in JSON)
3. ✅ Ensure all strings use double quotes (not single quotes)
4. ✅ Verify all brackets and braces are properly closed

---

## Configuration Examples

### Minimal Configuration
```json
{
  "mcpServers": {
    "verify-mcp-server-v2": {
      "type": "streamable-http",
      "url": "https://9.30.147.112:30804/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      }
    }
  }
}
```

### Configuration with Multiple Servers
```json
{
  "mcpServers": {
    "verify-mcp-server-v2": {
      "type": "streamable-http",
      "url": "https://9.30.147.112:30804/mcp",
      "headers": {
        "Authorization": "Bearer VERIFY_TOKEN"
      }
    },
    "qradar-mcp-server": {
      "type": "streamable-http",
      "url": "https://qradar.example.com:30804/mcp",
      "headers": {
        "Authorization": "Bearer QRADAR_TOKEN"
      }
    }
  }
}
```

### Configuration with Custom Headers
```json
{
  "mcpServers": {
    "verify-mcp-server-v2": {
      "type": "streamable-http",
      "url": "https://9.30.147.112:30804/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN_HERE",
        "X-Custom-Header": "custom-value",
        "User-Agent": "Bob-AI-Assistant/1.0"
      }
    }
  }
}
```

---

## Available Tools

Once connected, the following tools are available:

### 1. verify_discover
Search for API endpoints by keyword, category, or HTTP method.

**Parameters**:
- `query` (required): Search keyword
- `category` (optional): Filter by category name
- `method` (optional): Filter by HTTP method (GET, POST, PUT, DELETE)
- `offset` (optional): Pagination offset

**Example**:
```
verify_discover(query="user", method="GET")
```

### 2. verify_list_categories
List all API categories with endpoint counts.

**Parameters**: None

**Example**:
```
verify_list_categories()
```

### 3. verify_get_api_details
Get full parameter schema for a specific endpoint.

**Parameters**:
- `endpoint_id` (required): Endpoint identifier (e.g., "getUser")

**Example**:
```
verify_get_api_details(endpoint_id="getUser")
```

### 4. verify_execute
Execute an API endpoint.

**Parameters**:
- `endpoint_id` (required): Endpoint to execute
- `params` (optional): Query and path parameters
- `body` (optional): Request body for POST/PUT/PATCH

**Example**:
```
verify_execute(
  endpoint_id="getUser",
  params={"id": "109156235735988319"}
)
```

---

## Recommended Workflow

### For Discovery
1. Use `verify_list_categories()` to browse available categories
2. Use `verify_discover(query="keyword")` to find specific endpoints
3. Use `verify_get_api_details(endpoint_id="...")` to see parameters
4. Use `verify_execute(...)` to call the API

### For Development
1. Start with `verify_discover()` to find the right endpoint
2. Always call `verify_get_api_details()` before `verify_execute()`
3. Test with read operations (GET) before write operations (POST/PUT/DELETE)
4. Clean up test data after creation (use DELETE)

### For Testing
1. Create test users with unique identifiers (e.g., timestamp)
2. Verify creation with GET request
3. Test update operations
4. Clean up with DELETE request
5. Verify deletion with GET request (should return 404)

---

## Security Best Practices

### Token Management
- ✅ Never commit tokens to version control
- ✅ Use environment variables for tokens in CI/CD
- ✅ Rotate tokens regularly (every 90 days)
- ✅ Use separate tokens for dev/test/prod environments
- ✅ Revoke tokens immediately if compromised

### API Usage
- ✅ Use least-privilege scopes (only what's needed)
- ✅ Implement rate limiting in your code
- ✅ Log API calls for audit purposes
- ✅ Handle errors gracefully
- ✅ Validate input before sending to API

### Data Protection
- ✅ Don't log sensitive data (passwords, tokens, PII)
- ✅ Use HTTPS for all API calls (enforced by server)
- ✅ Encrypt tokens at rest
- ✅ Follow data retention policies
- ✅ Comply with GDPR/privacy regulations

---

## Support & Resources

### Documentation
- [IBM Security Verify API Documentation](https://docs.verify.ibm.com/verify/docs/api)
- [SCIM 2.0 Specification](https://datatracker.ietf.org/doc/html/rfc7644)
- [MCP Protocol Specification](https://modelcontextprotocol.io)

### Getting Help
- **Server Issues**: Contact server administrator
- **API Questions**: Refer to IBM Security Verify documentation
- **Bob Issues**: Check Bob documentation or support channels
- **Configuration Help**: Review this guide and troubleshooting section

### Test Files
- `test-queries.md` - 5 example queries with outputs
- `v2-comprehensive-test-results.md` - Full test results
- `testing-outcomes.md` - Known issues and workarounds
- `Verify-mcp-server-v2-bob-demo-guide.md` - Demo scenarios

---

## Next Steps

After successful setup:

1. ✅ Review `test-queries.md` for example queries
2. ✅ Read `v2-comprehensive-test-results.md` for test coverage
3. ✅ Check `testing-outcomes.md` for known issues
4. ✅ Try the demos in `Verify-mcp-server-v2-bob-demo-guide.md`
5. ✅ Start building your integration!

---

**Last Updated**: 2026-04-12  
**Version**: 2.0  
**Maintainer**: Bob AI Assistant