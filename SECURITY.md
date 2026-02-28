# Security Policy

## Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in this project, please report it privately to help us address it responsibly.

### How to Report

1. **Email:** ashrivastava@ibm.com
2. **Subject:** [SECURITY] Verify MCP Server - Brief Description
3. **Include:**
   - Type of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 5 business days
- **Resolution:** Varies by severity (critical issues prioritized)

### Security Best Practices

When deploying this project:

1. **Credentials Management**
   - Never commit API tokens, passwords, or secrets to version control
   - Use environment variables (`.env` files) for all sensitive configuration
   - Rotate credentials regularly

2. **Network Security**
   - Use HTTPS for all API communication
   - Deploy behind a firewall or VPN for internal use
   - Restrict network access to Verify endpoints

3. **Access Control**
   - Use unique API keys per user/client
   - Revoke keys immediately when no longer needed
   - Follow least privilege principle

4. **Monitoring**
   - Monitor for unusual API usage patterns
   - Review server logs regularly
   - Set up alerts for authentication failures

## Supported Versions

| Version | Supported |
| ------- | --------- |
| Latest  | ✅        |

## Disclosure Policy

We follow responsible disclosure. Security issues will be addressed promptly and disclosed after a fix is available.
