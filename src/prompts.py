"""MCP Prompt templates for IBM Security Verify.

Six IAM-specific report templates that instruct the AI to call specific
Verify tools in a defined order and format results consistently.
Every report uses ONLY live data — no fabricated values.

Prompts:
  1. user_access_review       — User inventory, entitlements, dormant accounts
  2. mfa_enrollment_report    — MFA method enrollment & coverage
  3. federation_health_report — SAML/OIDC federation config & health
  4. consent_compliance_report — Privacy consent posture & GDPR/CCPA gaps
  5. threat_detection_report   — ITDR events, anomalous logins, risk signals
  6. application_onboarding_guide — Step-by-step app registration & SSO setup
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP


def register_prompts(mcp: FastMCP) -> None:
    """Register all Verify report template prompts."""

    # ── Prompt 1: User Access Review ────────────────────────────────

    @mcp.prompt(
        name="user_access_review",
        description="Generate a User Access Review report: inventory, entitlements, last login, dormant accounts, and recommendations.",
    )
    def user_access_review(
        time_period: str = "last 30 days",
    ) -> str:
        return f"""# 🔐 User Access Review Report

**Reporting Period:** {time_period}
**Generated:** [current date/time]
**Tenant:** [tenant URL from connection]

---

## Instructions

Generate a comprehensive User Access Review using ONLY live data from IBM Security Verify.
Call the tools in the order specified below. Do NOT fabricate any values.

## Section 1: User Inventory Summary

**Action:** Call `verify_discover("user")` → then `verify_execute("getUsers", params={{"count": 100}})` to get user list.

Present:
- Total user count (from totalResults)
- Active vs inactive user breakdown
- Users by directory source (Cloud Directory, Federated, etc.)

| # | User Name | Display Name | Email | Active | Last Login |
|---|-----------|-------------|-------|--------|------------|

## Section 2: Group & Entitlement Analysis

**Action:** Call `verify_discover("group")` → then `verify_execute("getGroups")` to list all groups.

Present:
- Total groups
- Members per group
- Users with no group membership (orphaned)
- Over-privileged groups (groups with admin/owner roles)

| Group Name | Members | Description |
|-----------|---------|-------------|

## Section 3: Dormant Account Detection

**Action:** From the user data in Section 1, identify:
- Users who have not logged in during the reporting period ({time_period})
- Users with `active: false` status
- Accounts with no email address (service accounts?)

| User Name | Last Login | Status | Risk |
|-----------|-----------|--------|------|

## Section 4: Application Entitlements

**Action:** Call `verify_discover("application")` → then `verify_execute("getApplications")` to list applications.
For each application, check assigned users/groups.

| Application | Type | SSO Method | Assigned Users | Status |
|------------|------|-----------|---------------|--------|

## Section 5: Recommendations

Based on the findings above, provide:
1. **Immediate actions** — accounts to disable/remove
2. **Policy changes** — access policies to tighten
3. **Governance improvements** — certification campaigns to schedule
4. **Risk summary** — overall access risk rating (Low/Medium/High/Critical)

---
⚠️ Use ONLY real data from the Verify API calls. Do NOT fabricate or estimate values.
"""

    # ── Prompt 2: MFA Enrollment Report ─────────────────────────────

    @mcp.prompt(
        name="mfa_enrollment_report",
        description="Generate an MFA Enrollment Status report: method breakdown, unenrolled users, coverage gaps, and risk.",
    )
    def mfa_enrollment_report() -> str:
        return """# 🔑 MFA Enrollment Status Report

**Generated:** [current date/time]
**Tenant:** [tenant URL from connection]

---

## Instructions

Generate an MFA Enrollment report using ONLY live data from IBM Security Verify.
Call the tools in the order specified below. Do NOT fabricate any values.

## Section 1: MFA Method Inventory

**Action:** Call `verify_discover("authenticator")` and `verify_discover("factor")` to find MFA-related endpoints.
Then call relevant endpoints to list configured MFA methods.

Present:
- All available MFA methods (TOTP, FIDO2, SMS OTP, Email OTP, Push, QR Login, etc.)
- Whether each method is enabled/disabled at the tenant level
- Default MFA method (if configured)

| Method | Type | Status | Enrolled Users |
|--------|------|--------|---------------|

## Section 2: FIDO2 Registration Status

**Action:** Call `verify_discover("fido")` → then `verify_execute("getFIDO2Registrations")` or similar.

- Total FIDO2 registrations
- Users with multiple FIDO2 keys
- Registrations by authenticator type (platform vs cross-platform)

## Section 3: User Enrollment Coverage

**Action:** Cross-reference user list from `verify_execute("getUsers")` with MFA enrollment data.

- Total users vs MFA-enrolled users
- Enrollment percentage
- Users with NO second factor enrolled (high risk)
- Users with only one method enrolled (medium risk)

| Risk Level | Count | Percentage | Action Needed |
|-----------|-------|-----------|--------------|
| High (no MFA) | | | Enforce enrollment |
| Medium (single method) | | | Encourage backup method |
| Low (2+ methods) | | | No action |

## Section 4: MFA Policy Configuration

**Action:** Call `verify_discover("policy")` and `verify_discover("access")` to check if MFA is enforced.

- Is MFA required for all users?
- Conditional access policies that trigger MFA
- Bypass rules or exemptions

## Section 5: Recommendations

1. **Unenrolled users** — enforce MFA registration deadline
2. **Method diversity** — recommend FIDO2 as phishing-resistant option
3. **Policy gaps** — strengthen conditional access rules
4. **Risk score** — overall MFA posture rating

---
⚠️ Use ONLY real data from the Verify API calls. Do NOT fabricate or estimate values.
"""

    # ── Prompt 3: Federation Health Report ──────────────────────────

    @mcp.prompt(
        name="federation_health_report",
        description="Generate a Federation Health report: SAML/OIDC configurations, certificate expiry, trust relationships, and SSO errors.",
    )
    def federation_health_report() -> str:
        return """# 🌐 Federation Health Report

**Generated:** [current date/time]
**Tenant:** [tenant URL from connection]

---

## Instructions

Generate a Federation Health report using ONLY live data from IBM Security Verify.
Call the tools in the order specified below. Do NOT fabricate any values.

## Section 1: Identity Provider (IdP) Configuration

**Action:** Call `verify_discover("saml")` and `verify_discover("federation")` to find federation endpoints.
Then call relevant list endpoints.

Present:
- Configured SAML Identity Providers
- Configured OIDC Identity Providers
- Social login providers (Google, Facebook, etc.)

| Provider | Protocol | Status | Entity ID / Client ID | Last Used |
|---------|----------|--------|----------------------|-----------|

## Section 2: Service Provider (SP) / Relying Party Configuration

**Action:** Call `verify_discover("application")` → list applications with SSO configured.

- Applications using SAML SSO
- Applications using OIDC SSO
- Applications using WS-Federation

| Application | SSO Protocol | ACS URL / Redirect URI | Status |
|------------|-------------|----------------------|--------|

## Section 3: Certificate Health

**Action:** Call `verify_discover("certificate")` to find certificate-related endpoints.

- Signing certificates and their expiry dates
- Encryption certificates
- Certificates expiring within 90 days (WARNING)
- Expired certificates (CRITICAL)

| Certificate | Purpose | Expiry Date | Days Remaining | Status |
|------------|---------|-------------|---------------|--------|

## Section 4: SSO Configuration Validation

For each federation partner, verify:
- Metadata URL accessibility
- Assertion Consumer Service (ACS) URLs
- Name ID format alignment
- Attribute mapping completeness

## Section 5: Recommendations

1. **Certificate rotation** — renew certificates expiring within 90 days
2. **Unused federations** — disable or remove stale configurations
3. **Protocol upgrade** — migrate SAML-only apps to OIDC where possible
4. **Trust validation** — verify metadata URLs are current

---
⚠️ Use ONLY real data from the Verify API calls. Do NOT fabricate or estimate values.
"""

    # ── Prompt 4: Consent & Compliance Report ───────────────────────

    @mcp.prompt(
        name="consent_compliance_report",
        description="Generate a Privacy & Consent Compliance report: consent records, purpose coverage, GDPR/CCPA gaps, and data subject requests.",
    )
    def consent_compliance_report(
        framework: str = "GDPR",
    ) -> str:
        return f"""# 🛡️ Privacy & Consent Compliance Report

**Compliance Framework:** {framework}
**Generated:** [current date/time]
**Tenant:** [tenant URL from connection]

---

## Instructions

Generate a Privacy & Consent Compliance report using ONLY live data from IBM Security Verify.
Call the tools in the order specified below. Do NOT fabricate any values.

## Section 1: Consent Purpose Inventory

**Action:** Call `verify_discover("purpose")` and `verify_discover("consent")` → then list all configured consent purposes.

Present:
- All defined consent purposes
- Purpose categories (Marketing, Analytics, Functional, etc.)
- Default consent state (opt-in vs opt-out)
- Active vs inactive purposes

| Purpose | Category | Default State | Status | Description |
|---------|----------|--------------|--------|-------------|

## Section 2: Consent Collection Coverage

**Action:** Call relevant consent endpoints to check consent records.

- Users with full consent (all purposes accepted)
- Users with partial consent
- Users with no consent records
- Consent collection rate by purpose

## Section 3: Data Subject Rights ({framework})

**Action:** Call `verify_discover("data subject")` or `verify_discover("dpcm")` to find DSR endpoints.

- Data subject access requests (DSAR) processed
- Right to erasure requests
- Right to portability requests
- Average response time vs {framework} deadline (e.g., 30 days for GDPR)

## Section 4: Compliance Gap Analysis ({framework})

Based on the {framework} requirements, assess:
- **Lawful basis** — are consent purposes mapped to legal basis?
- **Data minimization** — are collected attributes limited to what's needed?
- **Retention policies** — are consent records retained appropriately?
- **Cross-border transfers** — are data residency requirements met?

| Requirement | Status | Gap | Remediation |
|------------|--------|-----|-------------|

## Section 5: Recommendations

1. **Missing consents** — users to contact for consent collection
2. **Purpose gaps** — new purposes to define
3. **Policy updates** — consent flows to revise
4. **Compliance score** — overall {framework} readiness (percentage)

---
⚠️ Use ONLY real data from the Verify API calls. Do NOT fabricate or estimate values.
"""

    # ── Prompt 5: Threat Detection Report ───────────────────────────

    @mcp.prompt(
        name="threat_detection_report",
        description="Generate a Threat Detection report: ITDR events, anomalous logins, impossible travel, compromised credentials, and risk signals.",
    )
    def threat_detection_report(
        time_period: str = "last 7 days",
    ) -> str:
        return f"""# 🚨 Identity Threat Detection Report

**Reporting Period:** {time_period}
**Generated:** [current date/time]
**Tenant:** [tenant URL from connection]

---

## Instructions

Generate an Identity Threat Detection & Response (ITDR) report using ONLY live data from IBM Security Verify.
Call the tools in the order specified below. Do NOT fabricate any values.

## Section 1: Authentication Events Overview

**Action:** Call `verify_discover("event")` and `verify_discover("report")` → then call relevant endpoints to get authentication events for {time_period}.

Present:
- Total authentication attempts
- Successful vs failed logins
- Failed login breakdown by reason (wrong password, locked account, MFA failure, etc.)
- Peak authentication times

## Section 2: Anomalous Login Detection

**Action:** Call `verify_discover("risk")` and `verify_discover("threat")` to find risk/threat endpoints.

Look for:
- Logins from unusual locations
- Impossible travel (logins from distant locations in short time)
- Logins from new devices
- Logins outside normal hours

| User | Event | Source IP | Location | Time | Risk Score |
|------|-------|----------|----------|------|-----------|

## Section 3: Account Compromise Indicators

Present:
- Accounts with multiple failed login attempts (brute force indicators)
- Password spray patterns (many users, same password pattern)
- Accounts locked due to excessive failures
- Credential stuffing indicators

| Indicator | Affected Users | Severity | Detection Time |
|----------|---------------|----------|---------------|

## Section 4: Adaptive Access Policy Triggers

**Action:** Call `verify_discover("access policy")` → check which policies triggered during {time_period}.

- Policies that triggered MFA step-up
- Policies that blocked access
- Risk-based authentication events

## Section 5: Recommendations

1. **Immediate response** — accounts to investigate/lock
2. **Policy tuning** — adaptive access rules to strengthen
3. **User education** — phishing awareness for targeted users
4. **Monitoring improvements** — additional signals to enable
5. **Threat level** — overall identity threat rating (Low/Medium/High/Critical)

---
⚠️ Use ONLY real data from the Verify API calls. Do NOT fabricate or estimate values.
"""

    # ── Prompt 6: Application Onboarding Guide ──────────────────────

    @mcp.prompt(
        name="application_onboarding_guide",
        description="Step-by-step guided workflow to register an application with SSO, assign entitlements, and configure access policies.",
    )
    def application_onboarding_guide(
        app_name: str = "MyApplication",
        sso_protocol: str = "OIDC",
    ) -> str:
        return f"""# 🚀 Application Onboarding Guide: {app_name}

**SSO Protocol:** {sso_protocol}
**Generated:** [current date/time]
**Tenant:** [tenant URL from connection]

---

## Instructions

Walk the user through onboarding "{app_name}" into IBM Security Verify with {sso_protocol} SSO.
Use the Verify API tools to execute each step. Confirm success at each stage before proceeding.

## Step 1: Check Existing Applications

**Action:** Call `verify_discover("application")` → then `verify_execute("getApplications")`.

- List current applications to confirm "{app_name}" doesn't already exist
- Note the total application count

## Step 2: Register the Application

**Action:** Call `verify_get_api_details("createApplication")` to get required parameters.
Then call `verify_execute("createApplication", body={{...}})`.

For {sso_protocol} configuration, include:
- Application name: {app_name}
- SSO protocol: {sso_protocol}
- Redirect URIs (ask user for these)
- Grant types (authorization_code recommended)

## Step 3: Configure SSO Settings

Based on {sso_protocol}:

**If OIDC:**
- Set redirect URIs
- Configure grant types
- Set token lifetimes
- Enable PKCE if SPA/mobile

**If SAML:**
- Upload SP metadata or configure manually
- Set ACS URL
- Configure Name ID format
- Map attributes (email, name, groups)

## Step 4: Assign Users / Groups

**Action:** Call `verify_discover("entitlement")` → find the entitlement assignment endpoint.

- Assign the application to specific groups or all users
- Configure access policies

## Step 5: Configure Access Policy

**Action:** Call `verify_discover("access policy")` → check or create an access policy for {app_name}.

Recommended policy:
- Require MFA for first login
- Allow remembered devices for 30 days
- Block access from high-risk locations

## Step 6: Test & Validate

Provide the user with:
- Application Client ID
- OIDC Discovery URL: `{{tenant}}/.well-known/openid-configuration`
- SAML Metadata URL: `{{tenant}}/saml/sps/saml20sp/saml20`
- Test login URL

## Checklist

- [ ] Application registered
- [ ] SSO configured ({sso_protocol})
- [ ] Users/groups assigned
- [ ] Access policy created
- [ ] Test login successful

---
⚠️ Use ONLY live data from the Verify API calls. Do NOT fabricate or estimate values.
"""
