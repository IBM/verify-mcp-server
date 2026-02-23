"""IBM Security Verify API schema — hardcoded catalog of all API endpoints.

Since IBM Verify does not expose a self-describing API catalog endpoint,
the full API surface is defined here as a structured dictionary. This is
the same approach used by the GCM MCP Server for products without live
API introspection.

Schema structure:
  VERIFY_API_SCHEMA = {
      "category_name": {
          "description": "...",
          "endpoints": {
              "endpoint_id": {
                  "method": "GET|POST|PUT|PATCH|DELETE",
                  "path": "/v2.0/Users",
                  "description": "...",
                  "params": { "param_name": {"type": "...", "required": bool, "description": "..."} },
                  "body": { "field_name": {"type": "...", "required": bool, "description": "..."} },
              }
          }
      }
  }
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class VerifyEndpoint:
    """A single Verify API endpoint with metadata."""

    endpoint_id: str
    category: str
    method: str
    path: str
    description: str
    params: dict[str, Any]
    body: dict[str, Any]

    @property
    def required_params(self) -> list[str]:
        """Parameter names marked as required."""
        req = []
        for name, spec in self.params.items():
            if spec.get("required"):
                req.append(name)
        for name, spec in self.body.items():
            if spec.get("required"):
                req.append(name)
        return req


# ══════════════════════════════════════════════════════════════════════
#  FULL IBM SECURITY VERIFY API SCHEMA
# ══════════════════════════════════════════════════════════════════════

VERIFY_API_SCHEMA: dict[str, dict[str, Any]] = {

    # ──────────────────────────────────────────────────────────────────
    #  IDENTITY MANAGEMENT
    # ──────────────────────────────────────────────────────────────────

    "Users Management v2.0 (SCIM)": {
        "description": "SCIM 2.0 user lifecycle management — create, search, update, delete users in Cloud Directory",
        "endpoints": {
            "getUsers": {
                "method": "GET",
                "path": "/v2.0/Users",
                "description": "Retrieves a list of users matching search filter criteria",
                "params": {
                    "filter": {"type": "string", "required": False, "description": "SCIM filter expression (e.g., userName eq \"john\")"},
                    "count": {"type": "integer", "required": False, "description": "Number of results to return"},
                    "startIndex": {"type": "integer", "required": False, "description": "1-based index of first result"},
                    "sortBy": {"type": "string", "required": False, "description": "Attribute to sort by"},
                    "sortOrder": {"type": "string", "required": False, "description": "ascending or descending"},
                    "attributes": {"type": "string", "required": False, "description": "Comma-separated list of attributes to return"},
                },
                "body": {},
            },
            "createUser": {
                "method": "POST",
                "path": "/v2.0/Users",
                "description": "Creates a user in Cloud Directory",
                "params": {
                    "notifyType": {"type": "string", "required": False, "description": "EMAIL or NONE — notification type"},
                    "themeId": {"type": "string", "required": False, "description": "Theme ID for email branding"},
                },
                "body": {
                    "schemas": {"type": "array", "required": True, "description": "SCIM schema URIs (urn:ietf:params:scim:schemas:core:2.0:User)"},
                    "userName": {"type": "string", "required": True, "description": "Unique user identifier"},
                    "emails": {"type": "array", "required": False, "description": "Array of email objects [{type, value}]"},
                    "name": {"type": "object", "required": False, "description": "{givenName, familyName, formatted}"},
                    "displayName": {"type": "string", "required": False, "description": "Display name"},
                    "active": {"type": "boolean", "required": False, "description": "Account active status"},
                    "password": {"type": "string", "required": False, "description": "Initial password"},
                    "phoneNumbers": {"type": "array", "required": False, "description": "Array of phone objects [{type, value}]"},
                },
            },
            "getUser": {
                "method": "GET",
                "path": "/v2.0/Users/{id}",
                "description": "Retrieves details of a specific user by ID",
                "params": {
                    "id": {"type": "string", "required": True, "description": "User ID (path parameter)"},
                    "attributes": {"type": "string", "required": False, "description": "Comma-separated attributes to return"},
                },
                "body": {},
            },
            "putUser": {
                "method": "PUT",
                "path": "/v2.0/Users/{id}",
                "description": "Replaces all user attributes (full update)",
                "params": {
                    "id": {"type": "string", "required": True, "description": "User ID (path parameter)"},
                },
                "body": {
                    "schemas": {"type": "array", "required": True, "description": "SCIM schema URIs"},
                    "userName": {"type": "string", "required": True, "description": "User name"},
                    "emails": {"type": "array", "required": False, "description": "Email objects"},
                    "name": {"type": "object", "required": False, "description": "Name object"},
                    "active": {"type": "boolean", "required": False, "description": "Active status"},
                },
            },
            "patchUser": {
                "method": "PATCH",
                "path": "/v2.0/Users/{id}",
                "description": "Modify one or more user attributes (partial update)",
                "params": {
                    "id": {"type": "string", "required": True, "description": "User ID (path parameter)"},
                },
                "body": {
                    "schemas": {"type": "array", "required": True, "description": "urn:ietf:params:scim:api:messages:2.0:PatchOp"},
                    "Operations": {"type": "array", "required": True, "description": "Array of {op, path, value} operations"},
                },
            },
            "deleteUser": {
                "method": "DELETE",
                "path": "/v2.0/Users/{id}",
                "description": "Deletes a user from Cloud Directory",
                "params": {
                    "id": {"type": "string", "required": True, "description": "User ID (path parameter)"},
                },
                "body": {},
            },
            "authenticateUser": {
                "method": "POST",
                "path": "/v2.0/Users/authentication",
                "description": "Authenticate a user name and password",
                "params": {},
                "body": {
                    "userName": {"type": "string", "required": True, "description": "User name"},
                    "password": {"type": "string", "required": True, "description": "Password"},
                    "schemas": {"type": "array", "required": True, "description": "SCIM schema URIs"},
                },
            },
            "getUserCardinality": {
                "method": "GET",
                "path": "/v2.0/Users",
                "description": "Retrieves user list metadata; use ListResponse.totalResults for tenant user count",
                "params": {
                    "count": {"type": "integer", "required": False, "description": "Page size (set small to fetch only metadata)"},
                    "startIndex": {"type": "integer", "required": False, "description": "1-based page start index"},
                    "filter": {"type": "string", "required": False, "description": "SCIM filter expression"},
                },
                "body": {},
            },
            "resetUserPassword": {
                "method": "PATCH",
                "path": "/v2.0/Users/{id}/password",
                "description": "Reset a user's password",
                "params": {
                    "id": {"type": "string", "required": True, "description": "User ID"},
                },
                "body": {
                    "password": {"type": "string", "required": True, "description": "New password"},
                    "schemas": {"type": "array", "required": True, "description": "SCIM schema URIs"},
                },
            },
            "bulkRequest": {
                "method": "POST",
                "path": "/v2.0/Bulk",
                "description": "Bulk create/update/delete users and groups (max 1000 operations)",
                "params": {
                    "notifyType": {"type": "string", "required": False, "description": "EMAIL or NONE"},
                },
                "body": {
                    "schemas": {"type": "array", "required": True, "description": "urn:ietf:params:scim:api:messages:2.0:BulkRequest"},
                    "Operations": {"type": "array", "required": True, "description": "Array of {method, path, bulkId, data} operations"},
                    "failOnErrors": {"type": "integer", "required": False, "description": "Max errors before termination"},
                },
            },
            "importUsers": {
                "method": "POST",
                "path": "/v2.0/Users/import",
                "description": "Import users from a CSV file",
                "params": {},
                "body": {},
            },
            "deleteUsers": {
                "method": "POST",
                "path": "/v2.0/Users/bulkdelete",
                "description": "Delete users from a CSV file",
                "params": {},
                "body": {},
            },
            "getImportJobs": {
                "method": "GET",
                "path": "/v2.0/Users/import/jobs",
                "description": "Retrieves a list of CSV import requests",
                "params": {},
                "body": {},
            },
            "getImportJob": {
                "method": "GET",
                "path": "/v2.0/Users/import/jobs/{id}",
                "description": "Retrieves details of a CSV import request",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Job ID"},
                },
                "body": {},
            },
            "cancelImportJob": {
                "method": "PUT",
                "path": "/v2.0/Users/import/jobs/{id}",
                "description": "Cancels a CSV import request",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Job ID"},
                },
                "body": {},
            },
            "deleteImportJob": {
                "method": "DELETE",
                "path": "/v2.0/Users/import/jobs/{id}",
                "description": "Deletes a CSV import request",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Job ID"},
                },
                "body": {},
            },
            "getImportHeaderNames": {
                "method": "GET",
                "path": "/v2.0/Users/import/headernames",
                "description": "Get the list of supported CSV header names",
                "params": {},
                "body": {},
            },
            "getReportees": {
                "method": "GET",
                "path": "/v2.0/Users/{id}/reportees",
                "description": "Retrieves a list of a manager's reportees",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Manager user ID"},
                    "filter": {"type": "string", "required": False, "description": "SCIM filter"},
                },
                "body": {},
            },
            "compareAttribute": {
                "method": "POST",
                "path": "/v2.0/Users/{id}/compare",
                "description": "Compare a clear text value to a custom hashed attribute value",
                "params": {
                    "id": {"type": "string", "required": True, "description": "User ID"},
                },
                "body": {},
            },
            "getScimCapabilities": {
                "method": "GET",
                "path": "/v2.0/ServiceProviderConfig",
                "description": "Retrieves the SCIM capabilities enabled for the tenant",
                "params": {},
                "body": {},
            },
        },
    },

    "Groups Management v2.0 (SCIM)": {
        "description": "SCIM 2.0 group management — create, list, update, delete groups and manage membership",
        "endpoints": {
            "getGroups": {
                "method": "GET",
                "path": "/v2.0/Groups",
                "description": "Retrieves a list of groups matching search filter criteria",
                "params": {
                    "filter": {"type": "string", "required": False, "description": "SCIM filter expression"},
                    "count": {"type": "integer", "required": False, "description": "Number of results"},
                    "startIndex": {"type": "integer", "required": False, "description": "Start index"},
                    "sortBy": {"type": "string", "required": False, "description": "Sort attribute"},
                    "sortOrder": {"type": "string", "required": False, "description": "ascending or descending"},
                },
                "body": {},
            },
            "createGroup": {
                "method": "POST",
                "path": "/v2.0/Groups",
                "description": "Creates a group in Cloud Directory",
                "params": {},
                "body": {
                    "schemas": {"type": "array", "required": True, "description": "SCIM schema URIs"},
                    "displayName": {"type": "string", "required": True, "description": "Group display name"},
                    "members": {"type": "array", "required": False, "description": "Array of {type, value} member objects"},
                },
            },
            "getGroup": {
                "method": "GET",
                "path": "/v2.0/Groups/{id}",
                "description": "Retrieves a specific group by ID",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Group ID"},
                },
                "body": {},
            },
            "putGroup": {
                "method": "PUT",
                "path": "/v2.0/Groups/{id}",
                "description": "Replaces a group's attributes (full update)",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Group ID"},
                },
                "body": {
                    "schemas": {"type": "array", "required": True, "description": "SCIM schema URIs"},
                    "displayName": {"type": "string", "required": True, "description": "Group name"},
                    "members": {"type": "array", "required": False, "description": "Members array"},
                },
            },
            "patchGroup": {
                "method": "PATCH",
                "path": "/v2.0/Groups/{id}",
                "description": "Modify group attributes (partial update — add/remove members)",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Group ID"},
                },
                "body": {
                    "schemas": {"type": "array", "required": True, "description": "PatchOp schema"},
                    "Operations": {"type": "array", "required": True, "description": "Patch operations"},
                },
            },
            "deleteGroup": {
                "method": "DELETE",
                "path": "/v2.0/Groups/{id}",
                "description": "Deletes a group",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Group ID"},
                },
                "body": {},
            },
            "importGroups": {
                "method": "POST",
                "path": "/v2.0/Groups/import",
                "description": "Import groups from a CSV file",
                "params": {},
                "body": {},
            },
            "getGroupCardinality": {
                "method": "GET",
                "path": "/v2.0/Groups",
                "description": "Retrieves group list metadata; use ListResponse.totalResults for group count",
                "params": {
                    "count": {"type": "integer", "required": False, "description": "Page size (set small to fetch only metadata)"},
                    "startIndex": {"type": "integer", "required": False, "description": "1-based page start index"},
                    "filter": {"type": "string", "required": False, "description": "SCIM filter expression"},
                },
                "body": {},
            },
        },
    },

    "User Self Care": {
        "description": "Authenticated user's own profile management — view/edit own account, change password",
        "endpoints": {
            "getSelfUser": {
                "method": "GET",
                "path": "/v2.0/Me",
                "description": "Retrieves the authenticated user's own account details",
                "params": {},
                "body": {},
            },
            "putSelfUser": {
                "method": "PUT",
                "path": "/v2.0/Me",
                "description": "Replaces the authenticated user's attributes",
                "params": {},
                "body": {},
            },
            "deleteSelfUser": {
                "method": "DELETE",
                "path": "/v2.0/Me",
                "description": "Delete the authenticated user's own account",
                "params": {},
                "body": {},
            },
            "getSelfPasswordPolicy": {
                "method": "GET",
                "path": "/v2.0/Me/passwordpolicy",
                "description": "Retrieves the authenticated user's effective password policy",
                "params": {},
                "body": {},
            },
            "getSelfPasswordPolicyLabels": {
                "method": "GET",
                "path": "/v2.0/Me/passwordpolicy/labels",
                "description": "Retrieves translated labels for the user's password policy",
                "params": {},
                "body": {},
            },
            "changeSelfPassword": {
                "method": "POST",
                "path": "/v2.0/Me/password",
                "description": "Change the authenticated user's password",
                "params": {},
                "body": {
                    "currentPassword": {"type": "string", "required": True, "description": "Current password"},
                    "newPassword": {"type": "string", "required": True, "description": "New password"},
                    "schemas": {"type": "array", "required": True, "description": "SCIM schema URIs"},
                },
            },
            "resetSelfPassword": {
                "method": "POST",
                "path": "/v2.0/Me/resetpassword",
                "description": "Reset password for the authenticated user",
                "params": {},
                "body": {},
            },
        },
    },

    "Dynamic Group Management": {
        "description": "Dynamic group rules — groups whose membership is computed from user attribute filters",
        "endpoints": {
            "listDynamicGroups": {
                "method": "GET",
                "path": "/v1.0/dynamicgroups",
                "description": "List all dynamic groups",
                "params": {},
                "body": {},
            },
            "createDynamicGroup": {
                "method": "POST",
                "path": "/v1.0/dynamicgroups",
                "description": "Create a dynamic group with attribute-based rules",
                "params": {},
                "body": {
                    "name": {"type": "string", "required": True, "description": "Group name"},
                    "description": {"type": "string", "required": False, "description": "Group description"},
                    "rules": {"type": "array", "required": True, "description": "Filter rules for membership"},
                },
            },
            "getDynamicGroup": {
                "method": "GET",
                "path": "/v1.0/dynamicgroups/{id}",
                "description": "Get a specific dynamic group by ID",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Dynamic group ID"},
                },
                "body": {},
            },
            "updateDynamicGroup": {
                "method": "PUT",
                "path": "/v1.0/dynamicgroups/{id}",
                "description": "Update a dynamic group",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Dynamic group ID"},
                },
                "body": {},
            },
            "deleteDynamicGroup": {
                "method": "DELETE",
                "path": "/v1.0/dynamicgroups/{id}",
                "description": "Delete a dynamic group",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Dynamic group ID"},
                },
                "body": {},
            },
            "getDynamicGroupUsers": {
                "method": "GET",
                "path": "/v1.0/dynamicgroups/{id}/users",
                "description": "List users matching a dynamic group's rules",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Dynamic group ID"},
                },
                "body": {},
            },
        },
    },

    "Identity Sources v2": {
        "description": "Manage identity source connections (Active Directory, LDAP, etc.)",
        "endpoints": {
            "getIdentitySources": {
                "method": "GET",
                "path": "/v2.0/identitysources",
                "description": "List all identity source instances",
                "params": {},
                "body": {},
            },
            "createIdentitySource": {
                "method": "POST",
                "path": "/v2.0/identitysources",
                "description": "Create a new identity source",
                "params": {},
                "body": {},
            },
            "getIdentitySource": {
                "method": "GET",
                "path": "/v2.0/identitysources/{id}",
                "description": "Get a specific identity source",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Identity source ID"},
                },
                "body": {},
            },
            "updateIdentitySource": {
                "method": "PUT",
                "path": "/v2.0/identitysources/{id}",
                "description": "Update an identity source",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Identity source ID"},
                },
                "body": {},
            },
            "deleteIdentitySource": {
                "method": "DELETE",
                "path": "/v2.0/identitysources/{id}",
                "description": "Delete an identity source",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Identity source ID"},
                },
                "body": {},
            },
        },
    },

    "Identity Source Types": {
        "description": "Available identity source type definitions",
        "endpoints": {
            "getIdentitySourceTypes": {
                "method": "GET",
                "path": "/v1.0/identitysourcetypes",
                "description": "Get available identity source types for the tenant",
                "params": {},
                "body": {},
            },
        },
    },

    # ──────────────────────────────────────────────────────────────────
    #  OPENID CONNECT
    # ──────────────────────────────────────────────────────────────────

    "OpenID Connect": {
        "description": "OIDC provider operations — metadata, authorize, token, introspect, revoke, userinfo",
        "endpoints": {
            "getOIDCMetadata": {
                "method": "GET",
                "path": "/v1.0/endpoint/default/.well-known/openid-configuration",
                "description": "Get the OIDC provider's metadata",
                "params": {},
                "body": {},
            },
            "getOIDCJWKS": {
                "method": "GET",
                "path": "/v1.0/endpoint/default/jwks",
                "description": "Get the provider's JSON Web Key Set (JWKS)",
                "params": {},
                "body": {},
            },
            "getToken": {
                "method": "POST",
                "path": "/v1.0/endpoint/default/token",
                "description": "Get an access token (authorization_code, client_credentials, refresh_token, etc.)",
                "params": {},
                "body": {
                    "grant_type": {"type": "string", "required": True, "description": "authorization_code, client_credentials, refresh_token, password, urn:ietf:params:oauth:grant-type:device_code"},
                    "client_id": {"type": "string", "required": True, "description": "Client ID"},
                    "client_secret": {"type": "string", "required": False, "description": "Client secret"},
                    "code": {"type": "string", "required": False, "description": "Authorization code (for authorization_code grant)"},
                    "redirect_uri": {"type": "string", "required": False, "description": "Redirect URI"},
                    "refresh_token": {"type": "string", "required": False, "description": "Refresh token"},
                    "scope": {"type": "string", "required": False, "description": "Space-separated scopes"},
                },
            },
            "introspectToken": {
                "method": "POST",
                "path": "/v1.0/endpoint/default/introspect",
                "description": "Introspect a token to check its validity and claims",
                "params": {},
                "body": {
                    "token": {"type": "string", "required": True, "description": "Token to introspect"},
                    "client_id": {"type": "string", "required": True, "description": "Client ID"},
                    "client_secret": {"type": "string", "required": True, "description": "Client secret"},
                },
            },
            "revokeToken": {
                "method": "POST",
                "path": "/v1.0/endpoint/default/revoke",
                "description": "Revoke a token",
                "params": {},
                "body": {
                    "token": {"type": "string", "required": True, "description": "Token to revoke"},
                    "client_id": {"type": "string", "required": True, "description": "Client ID"},
                    "client_secret": {"type": "string", "required": True, "description": "Client secret"},
                },
            },
            "getUserInfo": {
                "method": "GET",
                "path": "/v1.0/endpoint/default/userinfo",
                "description": "Retrieve authenticated user information from the OIDC provider",
                "params": {},
                "body": {},
            },
            "createDynamicClient": {
                "method": "POST",
                "path": "/v1.0/endpoint/default/registration",
                "description": "Create a dynamic OIDC client registration",
                "params": {},
                "body": {},
            },
            "getDynamicClient": {
                "method": "GET",
                "path": "/v1.0/endpoint/default/registration/{id}",
                "description": "Read a dynamic OIDC client",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Client ID"},
                },
                "body": {},
            },
            "deleteDynamicClient": {
                "method": "DELETE",
                "path": "/v1.0/endpoint/default/registration/{id}",
                "description": "Delete a dynamic OIDC client",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Client ID"},
                },
                "body": {},
            },
            "deviceAuthorize": {
                "method": "POST",
                "path": "/v1.0/endpoint/default/device_authorization",
                "description": "Authorize a device to use OIDC (device flow)",
                "params": {},
                "body": {
                    "client_id": {"type": "string", "required": True, "description": "Client ID"},
                    "scope": {"type": "string", "required": False, "description": "Scopes"},
                },
            },
        },
    },

    # ──────────────────────────────────────────────────────────────────
    #  AUTHENTICATION & MFA
    # ──────────────────────────────────────────────────────────────────

    "Authentication Factors 2.0": {
        "description": "Manage MFA factor enrollments for users",
        "endpoints": {
            "listFactorEnrollments": {
                "method": "GET",
                "path": "/v2.0/factors",
                "description": "List all factor enrollments for the authenticated user",
                "params": {
                    "search": {"type": "string", "required": False, "description": "Search filter"},
                },
                "body": {},
            },
        },
    },

    "Email OTP 2.0": {
        "description": "Email one-time password enrollment and verification",
        "endpoints": {
            "listEmailOTPEnrollments": {
                "method": "GET",
                "path": "/v2.0/factors/emailotp",
                "description": "List email OTP enrollments",
                "params": {
                    "search": {"type": "string", "required": False, "description": "Filter"},
                },
                "body": {},
            },
            "createEmailOTPEnrollment": {
                "method": "POST",
                "path": "/v2.0/factors/emailotp",
                "description": "Create a new email OTP enrollment",
                "params": {},
                "body": {
                    "emailAddress": {"type": "string", "required": True, "description": "Email address for OTP delivery"},
                },
            },
            "getEmailOTPEnrollment": {
                "method": "GET",
                "path": "/v2.0/factors/emailotp/{id}",
                "description": "Get a specific email OTP enrollment",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Enrollment ID"},
                },
                "body": {},
            },
            "deleteEmailOTPEnrollment": {
                "method": "DELETE",
                "path": "/v2.0/factors/emailotp/{id}",
                "description": "Delete an email OTP enrollment",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Enrollment ID"},
                },
                "body": {},
            },
        },
    },

    "SMS OTP 2.0": {
        "description": "SMS one-time password enrollment and verification",
        "endpoints": {
            "listSMSOTPEnrollments": {
                "method": "GET",
                "path": "/v2.0/factors/smsotp",
                "description": "List SMS OTP enrollments",
                "params": {
                    "search": {"type": "string", "required": False, "description": "Filter"},
                },
                "body": {},
            },
            "createSMSOTPEnrollment": {
                "method": "POST",
                "path": "/v2.0/factors/smsotp",
                "description": "Create a new SMS OTP enrollment",
                "params": {},
                "body": {
                    "phoneNumber": {"type": "string", "required": True, "description": "Phone number for SMS delivery"},
                },
            },
            "deleteSMSOTPEnrollment": {
                "method": "DELETE",
                "path": "/v2.0/factors/smsotp/{id}",
                "description": "Delete an SMS OTP enrollment",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Enrollment ID"},
                },
                "body": {},
            },
        },
    },

    "TOTP 2.0": {
        "description": "Time-based one-time password enrollment and verification",
        "endpoints": {
            "listTOTPEnrollments": {
                "method": "GET",
                "path": "/v2.0/factors/totp",
                "description": "List TOTP enrollments",
                "params": {},
                "body": {},
            },
            "createTOTPEnrollment": {
                "method": "POST",
                "path": "/v2.0/factors/totp",
                "description": "Create a new TOTP enrollment",
                "params": {},
                "body": {},
            },
            "deleteTOTPEnrollment": {
                "method": "DELETE",
                "path": "/v2.0/factors/totp/{id}",
                "description": "Delete a TOTP enrollment",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Enrollment ID"},
                },
                "body": {},
            },
        },
    },

    "Voice OTP": {
        "description": "Voice one-time password enrollment and verification",
        "endpoints": {
            "listVoiceOTPEnrollments": {
                "method": "GET",
                "path": "/v2.0/factors/voiceotp",
                "description": "List voice OTP enrollments",
                "params": {},
                "body": {},
            },
            "createVoiceOTPEnrollment": {
                "method": "POST",
                "path": "/v2.0/factors/voiceotp",
                "description": "Create a new voice OTP enrollment",
                "params": {},
                "body": {
                    "phoneNumber": {"type": "string", "required": True, "description": "Phone number for voice OTP"},
                },
            },
            "deleteVoiceOTPEnrollment": {
                "method": "DELETE",
                "path": "/v2.0/factors/voiceotp/{id}",
                "description": "Delete a voice OTP enrollment",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Enrollment ID"},
                },
                "body": {},
            },
        },
    },

    "OTP Verification": {
        "description": "One-time password verification (email, SMS, voice, TOTP)",
        "endpoints": {
            "createOTPVerification": {
                "method": "POST",
                "path": "/v2.0/factors/verification",
                "description": "Create an OTP verification transaction (sends OTP to user)",
                "params": {},
                "body": {
                    "enrollmentId": {"type": "string", "required": True, "description": "Factor enrollment ID"},
                },
            },
            "verifyOTP": {
                "method": "POST",
                "path": "/v2.0/factors/verification/{id}",
                "description": "Verify an OTP code",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Verification transaction ID"},
                },
                "body": {
                    "otp": {"type": "string", "required": True, "description": "OTP code to verify"},
                },
            },
        },
    },

    "FIDO2": {
        "description": "FIDO2/WebAuthn registration and authentication",
        "endpoints": {
            "getFIDORegistrations": {
                "method": "GET",
                "path": "/v2.0/factors/fido2",
                "description": "List FIDO2 registrations for the user",
                "params": {},
                "body": {},
            },
            "createFIDORegistration": {
                "method": "POST",
                "path": "/v2.0/factors/fido2",
                "description": "Initiate a FIDO2 registration",
                "params": {},
                "body": {},
            },
            "deleteFIDORegistration": {
                "method": "DELETE",
                "path": "/v2.0/factors/fido2/{id}",
                "description": "Delete a FIDO2 registration",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Registration ID"},
                },
                "body": {},
            },
        },
    },

    "QR Code Login": {
        "description": "QR code-based login flow — generate and verify QR codes",
        "endpoints": {
            "createQRVerification": {
                "method": "POST",
                "path": "/v2.0/factors/qr",
                "description": "Create a QR code login verification",
                "params": {},
                "body": {},
            },
            "getQRVerification": {
                "method": "GET",
                "path": "/v2.0/factors/qr/{id}",
                "description": "Poll status of a QR code verification",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Verification ID"},
                },
                "body": {},
            },
        },
    },

    "Knowledge Questions": {
        "description": "Knowledge-based authentication (security questions)",
        "endpoints": {
            "getKQEnrollments": {
                "method": "GET",
                "path": "/v2.0/factors/questions",
                "description": "Get knowledge question enrollments",
                "params": {},
                "body": {},
            },
            "updateKQEnrollments": {
                "method": "PUT",
                "path": "/v2.0/factors/questions",
                "description": "Set/update knowledge question answers",
                "params": {},
                "body": {},
            },
        },
    },

    "Password Authentication": {
        "description": "Password-based authentication methods",
        "endpoints": {
            "getPasswordMethods": {
                "method": "GET",
                "path": "/v2.0/factors/password",
                "description": "Get available password authentication methods",
                "params": {},
                "body": {},
            },
        },
    },

    "Signature Authentication": {
        "description": "Digital signature authentication",
        "endpoints": {
            "getSignatureMethods": {
                "method": "GET",
                "path": "/v2.0/factors/signatures",
                "description": "Get signature authentication methods",
                "params": {},
                "body": {},
            },
        },
    },

    "Authenticators": {
        "description": "IBM Verify Authenticator app registrations",
        "endpoints": {
            "getAuthenticators": {
                "method": "GET",
                "path": "/v1.0/authenticators",
                "description": "List all registered authenticators (IBM Verify app instances)",
                "params": {
                    "search": {"type": "string", "required": False, "description": "Search filter"},
                },
                "body": {},
            },
            "deleteAuthenticator": {
                "method": "DELETE",
                "path": "/v1.0/authenticators/{id}",
                "description": "Delete an authenticator registration",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Authenticator ID"},
                },
                "body": {},
            },
        },
    },

    "Session Management": {
        "description": "Manage user authentication sessions",
        "endpoints": {
            "evictSessions": {
                "method": "POST",
                "path": "/v1.0/auth/sessions",
                "description": "Evict (terminate) user sessions",
                "params": {},
                "body": {
                    "userId": {"type": "string", "required": True, "description": "User ID to evict sessions for"},
                },
            },
        },
    },

    "Token Exchange": {
        "description": "Exchange authentication tokens between providers",
        "endpoints": {
            "exchangeToken": {
                "method": "POST",
                "path": "/v1.0/auth/session",
                "description": "Exchange an authentication token",
                "params": {},
                "body": {},
            },
        },
    },

    "Social JWT Exchange": {
        "description": "Exchange social provider JWT tokens",
        "endpoints": {
            "exchangeSocialToken": {
                "method": "POST",
                "path": "/v1.0/socialjwt/exchange",
                "description": "Exchange a social provider JWT token for a Verify token",
                "params": {},
                "body": {},
            },
        },
    },

    # ──────────────────────────────────────────────────────────────────
    #  FEDERATION
    # ──────────────────────────────────────────────────────────────────

    "SAML 2.0 Federations": {
        "description": "SAML 2.0 federation management — partner connections",
        "endpoints": {
            "listFederations": {
                "method": "GET",
                "path": "/v1.0/saml/federations",
                "description": "List all SAML 2.0 federations",
                "params": {},
                "body": {},
            },
            "createFederation": {
                "method": "POST",
                "path": "/v1.0/saml/federations",
                "description": "Create a SAML 2.0 federation",
                "params": {},
                "body": {},
            },
            "getFederation": {
                "method": "GET",
                "path": "/v1.0/saml/federations/{id}",
                "description": "Get a specific federation",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Federation ID"},
                },
                "body": {},
            },
            "updateFederation": {
                "method": "PUT",
                "path": "/v1.0/saml/federations/{id}",
                "description": "Update a federation",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Federation ID"},
                },
                "body": {},
            },
            "deleteFederation": {
                "method": "DELETE",
                "path": "/v1.0/saml/federations/{id}",
                "description": "Delete a federation",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Federation ID"},
                },
                "body": {},
            },
        },
    },

    "SAML 2.0 Alias Management": {
        "description": "Manage SAML 2.0 IdP aliases",
        "endpoints": {
            "listAliases": {
                "method": "GET",
                "path": "/v1.0/saml/alias",
                "description": "List all SAML 2.0 aliases",
                "params": {},
                "body": {},
            },
            "createAlias": {
                "method": "POST",
                "path": "/v1.0/saml/alias",
                "description": "Create a SAML alias",
                "params": {},
                "body": {},
            },
            "deleteAlias": {
                "method": "DELETE",
                "path": "/v1.0/saml/alias/{id}",
                "description": "Delete a SAML alias",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Alias ID"},
                },
                "body": {},
            },
        },
    },

    "SAML 2.0 SP Alias Management": {
        "description": "Manage SAML 2.0 SP aliases",
        "endpoints": {
            "listSPAliases": {
                "method": "GET",
                "path": "/v1.0/saml/spalias",
                "description": "List all SAML 2.0 SP aliases",
                "params": {},
                "body": {},
            },
        },
    },

    "OIDC Federation": {
        "description": "OpenID Connect federation settings",
        "endpoints": {
            "getOIDCFederationSettings": {
                "method": "GET",
                "path": "/v1.0/oidc/federation",
                "description": "Read OIDC federation settings",
                "params": {},
                "body": {},
            },
            "updateOIDCFederationSettings": {
                "method": "PUT",
                "path": "/v1.0/oidc/federation",
                "description": "Update OIDC federation settings",
                "params": {},
                "body": {},
            },
        },
    },

    "OIDC Grant Management": {
        "description": "Manage OIDC consent grants",
        "endpoints": {
            "listGrants": {
                "method": "GET",
                "path": "/v1.0/appgrants",
                "description": "List all OIDC grants",
                "params": {},
                "body": {},
            },
        },
    },

    "OIDC Dynamic Client Profile": {
        "description": "OIDC dynamic client registration profiles",
        "endpoints": {
            "getClientProfile": {
                "method": "GET",
                "path": "/v1.0/dynamic-client-profile",
                "description": "Read dynamic client profile",
                "params": {},
                "body": {},
            },
        },
    },

    "OIDC Client Secret Rotation": {
        "description": "Rotate OIDC client secrets",
        "endpoints": {
            "listClientSecrets": {
                "method": "GET",
                "path": "/v2.0/clients/{id}/secrets",
                "description": "Read client secrets for rotation",
                "params": {
                    "id": {"type": "string", "required": True, "description": "API client ID"},
                },
                "body": {},
            },
        },
    },

    "OIDC STS Clients": {
        "description": "OIDC Security Token Service clients",
        "endpoints": {
            "listSTSClients": {
                "method": "GET",
                "path": "/v1.0/sts/oauth/clients",
                "description": "Read STS clients",
                "params": {},
                "body": {},
            },
        },
    },

    "OIDC Token Types": {
        "description": "OIDC token type configuration",
        "endpoints": {
            "listTokenTypes": {
                "method": "GET",
                "path": "/v1.0/sts/tokentypes",
                "description": "Read token types",
                "params": {},
                "body": {},
            },
        },
    },

    "WS Federation": {
        "description": "WS-Federation management",
        "endpoints": {
            "getWSFedSettings": {
                "method": "GET",
                "path": "/v1.0/wsf/federations/trace",
                "description": "Get WS-Federation settings",
                "params": {},
                "body": {},
            },
        },
    },

    "IdP Attribute Mappings": {
        "description": "Identity Provider attribute mapping configuration",
        "endpoints": {
            "getAttributeMappings": {
                "method": "GET",
                "path": "/v1.0/config/identitysources/attributemappings",
                "description": "Get global IdP attribute mapping configuration",
                "params": {},
                "body": {},
            },
            "updateAttributeMappings": {
                "method": "PUT",
                "path": "/v1.0/config/identitysources/attributemappings",
                "description": "Update IdP attribute mappings",
                "params": {},
                "body": {},
            },
        },
    },

    # ──────────────────────────────────────────────────────────────────
    #  ACCESS & POLICY
    # ──────────────────────────────────────────────────────────────────

    "Access Policy Management v5.0": {
        "description": "Risk-based access policies — adaptive authentication rules",
        "endpoints": {
            "listAccessPolicies": {
                "method": "GET",
                "path": "/v5.0/policyvault/accesspolicy",
                "description": "List all access policies",
                "params": {},
                "body": {},
            },
            "createAccessPolicy": {
                "method": "POST",
                "path": "/v5.0/policyvault/accesspolicy",
                "description": "Create a new access policy",
                "params": {},
                "body": {},
            },
            "getAccessPolicy": {
                "method": "GET",
                "path": "/v5.0/policyvault/accesspolicy/{id}",
                "description": "Get a specific access policy",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Policy ID"},
                },
                "body": {},
            },
            "updateAccessPolicy": {
                "method": "PUT",
                "path": "/v5.0/policyvault/accesspolicy/{id}",
                "description": "Update an access policy",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Policy ID"},
                },
                "body": {},
            },
            "deleteAccessPolicy": {
                "method": "DELETE",
                "path": "/v5.0/policyvault/accesspolicy/{id}",
                "description": "Delete an access policy",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Policy ID"},
                },
                "body": {},
            },
        },
    },

    "Application Access": {
        "description": "Application access operations and search",
        "endpoints": {
            "searchApplicationAccess": {
                "method": "GET",
                "path": "/v1.0/applications",
                "description": "Search application access operations",
                "params": {
                    "search": {"type": "string", "required": False, "description": "Search filter"},
                },
                "body": {},
            },
        },
    },

    "Entitlement Management": {
        "description": "Application entitlement assignments",
        "endpoints": {
            "getEntitlementRightValues": {
                "method": "GET",
                "path": "/v1.0/entitlements",
                "description": "Get assignment right values for entitlements",
                "params": {},
                "body": {},
            },
        },
    },

    "Entitlement Management v2": {
        "description": "Application entitlement management v2",
        "endpoints": {
            "getEntitlementRightValuesV2": {
                "method": "GET",
                "path": "/v2.0/assignments/{assignment}/rights",
                "description": "Get assignment right values (v2)",
                "params": {
                    "assignment": {"type": "string", "required": True, "description": "Assignment ID"},
                },
                "body": {},
            },
        },
    },

    "Access Management": {
        "description": "Access management — self-service entitlements",
        "endpoints": {
            "getSelfEntitlements": {
                "method": "GET",
                "path": "/v1.0/access/entitlements/{entitlement}/children",
                "description": "Get entitlement children for self",
                "params": {
                    "entitlement": {"type": "string", "required": True, "description": "Entitlement ID"},
                },
                "body": {},
            },
        },
    },

    "Access Request Management v1.0": {
        "description": "Request-based access provisioning",
        "endpoints": {
            "getRequestableAccess": {
                "method": "GET",
                "path": "/v1.0/access/entitlements/{entitlement}",
                "description": "Get requestable access details for the current user",
                "params": {
                    "entitlement": {"type": "string", "required": True, "description": "Entitlement ID"},
                },
                "body": {},
            },
        },
    },

    # ──────────────────────────────────────────────────────────────────
    #  PRIVACY & CONSENT (DPCM)
    # ──────────────────────────────────────────────────────────────────

    "Data Privacy & Consent Management": {
        "description": "Configure privacy purposes, attributes, and access types (admin)",
        "endpoints": {
            "listPurposes": {
                "method": "GET",
                "path": "/config/v1.0/privacy/purposes",
                "description": "List all configured privacy purposes",
                "params": {},
                "body": {},
            },
            "createPurpose": {
                "method": "POST",
                "path": "/config/v1.0/privacy/purposes",
                "description": "Create a new privacy purpose",
                "params": {},
                "body": {
                    "name": {"type": "string", "required": True, "description": "Purpose name"},
                    "description": {"type": "string", "required": False, "description": "Purpose description"},
                },
            },
            "getPurpose": {
                "method": "GET",
                "path": "/config/v1.0/privacy/purposes/{id}",
                "description": "Get a specific privacy purpose",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Purpose ID"},
                },
                "body": {},
            },
            "updatePurpose": {
                "method": "PUT",
                "path": "/config/v1.0/privacy/purposes/{id}",
                "description": "Update a privacy purpose",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Purpose ID"},
                },
                "body": {},
            },
            "deletePurpose": {
                "method": "DELETE",
                "path": "/config/v1.0/privacy/purposes/{id}",
                "description": "Delete a privacy purpose",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Purpose ID"},
                },
                "body": {},
            },
            "patchPurposeRelation": {
                "method": "PATCH",
                "path": "/config/v1.0/privacy/purposes/{id}",
                "description": "Patch purpose relations (add/remove attributes, access types)",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Purpose ID"},
                },
                "body": {},
            },
        },
    },

    "Data Privacy & Consent (Runtime)": {
        "description": "Runtime consent management — create/update consent records, data subject presentation",
        "endpoints": {
            "createConsent": {
                "method": "POST",
                "path": "/v1.0/privacy/consents",
                "description": "Create or update a consent record",
                "params": {},
                "body": {
                    "purposeId": {"type": "string", "required": True, "description": "Purpose ID"},
                    "state": {"type": "integer", "required": True, "description": "1=Allow, 2=Deny, 3=OptIn, 4=OptOut, 5=Transparency"},
                    "subjectId": {"type": "string", "required": False, "description": "User ID (Cloud Directory ID if internal)"},
                    "isExternalSubject": {"type": "boolean", "required": False, "description": "Whether subjectId is external"},
                    "attributeId": {"type": "string", "required": False, "description": "Attribute ID"},
                    "attributeValue": {"type": "string", "required": False, "description": "Attribute value"},
                    "accessTypeId": {"type": "string", "required": False, "description": "Access type ID"},
                },
            },
            "bulkConsent": {
                "method": "PATCH",
                "path": "/v1.0/privacy/consents",
                "description": "Bulk create or patch consent records",
                "params": {},
                "body": {},
            },
            "dataSubjectPresentation": {
                "method": "POST",
                "path": "/v1.0/privacy/data-subject-presentation",
                "description": "Present data subject information to the user (consent page data)",
                "params": {},
                "body": {},
            },
            "dataUsageApproval": {
                "method": "POST",
                "path": "/v1.0/privacy/data-usage-approval",
                "description": "Provides the data usage approval",
                "params": {},
                "body": {},
            },
        },
    },

    "External Consent Providers": {
        "description": "Manage external consent provider integrations",
        "endpoints": {
            "assessDataUsage": {
                "method": "POST",
                "path": "/config/v1.0/privacy/consent-providers/assess",
                "description": "Assess data usage approval via external provider",
                "params": {},
                "body": {},
            },
            "listConsentProviders": {
                "method": "GET",
                "path": "/config/v1.0/privacy/consent-providers",
                "description": "List configured external consent providers",
                "params": {},
                "body": {},
            },
            "createConsentProvider": {
                "method": "POST",
                "path": "/config/v1.0/privacy/consent-providers",
                "description": "Create an external consent provider",
                "params": {},
                "body": {},
            },
            "deleteConsentProvider": {
                "method": "DELETE",
                "path": "/config/v1.0/privacy/consent-providers/{id}",
                "description": "Delete an external consent provider",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Provider ID"},
                },
                "body": {},
            },
        },
    },

    # ──────────────────────────────────────────────────────────────────
    #  CONFIGURATION
    # ──────────────────────────────────────────────────────────────────

    "API Clients": {
        "description": "Manage API client registrations (OAuth2 clients for machine-to-machine access)",
        "endpoints": {
            "listAPIClients": {
                "method": "GET",
                "path": "/v1.0/apiclients",
                "description": "List all API clients",
                "params": {
                    "pagination": {"type": "string", "required": False, "description": "Pagination params (count, page, limit)"},
                    "sort": {"type": "string", "required": False, "description": "Sort by clientId, clientName, enabled"},
                    "search": {"type": "string", "required": False, "description": "Search filter on clientId, clientName, enabled"},
                    "filter": {"type": "string", "required": False, "description": "Include/exclude fields"},
                },
                "body": {},
            },
            "createAPIClient": {
                "method": "POST",
                "path": "/v1.0/apiclients",
                "description": "Create a new API client",
                "params": {},
                "body": {
                    "clientName": {"type": "string", "required": True, "description": "Client name"},
                    "entitlements": {"type": "array", "required": True, "description": "Array of entitlement IDs"},
                },
            },
            "getAPIClient": {
                "method": "GET",
                "path": "/v1.0/apiclients/{id}",
                "description": "Get a specific API client",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Client ID"},
                },
                "body": {},
            },
            "updateAPIClient": {
                "method": "PUT",
                "path": "/v1.0/apiclients/{id}",
                "description": "Update a specific API client",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Client ID"},
                },
                "body": {},
            },
            "deleteAPIClient": {
                "method": "DELETE",
                "path": "/v1.0/apiclients/{id}",
                "description": "Delete an API client",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Client ID"},
                },
                "body": {},
            },
            "bulkDeleteAPIClients": {
                "method": "PATCH",
                "path": "/v1.0/apiclients",
                "description": "Bulk delete API clients",
                "params": {},
                "body": {},
            },
            "getAPIClientYAML": {
                "method": "GET",
                "path": "/v1.0/apiclients/{id}/yaml",
                "description": "Get YAML credentials for a specific API client",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Client ID"},
                },
                "body": {},
            },
        },
    },

    "Account Expiration Configuration": {
        "description": "Configure account expiration policies",
        "endpoints": {
            "getAccountExpirationConfig": {
                "method": "GET",
                "path": "/v1.0/config/accountexpiration",
                "description": "Get account expiration global configuration",
                "params": {},
                "body": {},
            },
            "updateAccountExpirationConfig": {
                "method": "PUT",
                "path": "/v1.0/config/accountexpiration",
                "description": "Update account expiration configuration",
                "params": {},
                "body": {},
            },
        },
    },

    "Password Policy Management v2.0": {
        "description": "Password policy configuration v2",
        "endpoints": {
            "getPasswordPolicy": {
                "method": "GET",
                "path": "/v3.0/PasswordPolicies",
                "description": "Get password policy for the tenant",
                "params": {},
                "body": {},
            },
            "updatePasswordPolicy": {
                "method": "PUT",
                "path": "/v3.0/PasswordPolicies",
                "description": "Update the password policy",
                "params": {},
                "body": {},
            },
        },
    },

    "Password Policy Management v3.0": {
        "description": "Password policy configuration v3 — multiple policies",
        "endpoints": {
            "listPasswordPolicies": {
                "method": "GET",
                "path": "/v3.0/PasswordPolicies",
                "description": "List all password policies",
                "params": {},
                "body": {},
            },
            "createPasswordPolicy": {
                "method": "POST",
                "path": "/v3.0/PasswordPolicies",
                "description": "Create a password policy",
                "params": {},
                "body": {},
            },
            "getPasswordPolicyV3": {
                "method": "GET",
                "path": "/v3.0/PasswordPolicies/{id}",
                "description": "Get a specific password policy",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Policy ID"},
                },
                "body": {},
            },
            "updatePasswordPolicyV3": {
                "method": "PUT",
                "path": "/v3.0/PasswordPolicies/{id}",
                "description": "Update a password policy",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Policy ID"},
                },
                "body": {},
            },
            "deletePasswordPolicyV3": {
                "method": "DELETE",
                "path": "/v3.0/PasswordPolicies/{id}",
                "description": "Delete a password policy",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Policy ID"},
                },
                "body": {},
            },
        },
    },

    "Dictionary Policy Management 3.0": {
        "description": "Password dictionary policy management",
        "endpoints": {
            "getDictPolicy": {
                "method": "GET",
                "path": "/v3.0/DictionaryPolicy",
                "description": "Get dictionary policy",
                "params": {},
                "body": {},
            },
        },
    },

    "Password Dictionary Management 3.0": {
        "description": "Manage password dictionaries",
        "endpoints": {
            "listPasswordDictionaries": {
                "method": "GET",
                "path": "/v3.0/PasswordDictionary",
                "description": "List password dictionaries",
                "params": {},
                "body": {},
            },
            "deletePasswordDictionary": {
                "method": "DELETE",
                "path": "/v3.0/PasswordDictionary/{id}",
                "description": "Delete a password dictionary",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Dictionary ID"},
                },
                "body": {},
            },
        },
    },

    "Tenant Properties v2.0": {
        "description": "Tenant-level property configuration",
        "endpoints": {
            "getTenantProperties": {
                "method": "GET",
                "path": "/v2.0/tenant/properties",
                "description": "Get tenant properties",
                "params": {},
                "body": {},
            },
            "updateTenantProperties": {
                "method": "PUT",
                "path": "/v2.0/tenant/properties",
                "description": "Update tenant properties",
                "params": {},
                "body": {},
            },
        },
    },

    "Tenant Policy Configuration": {
        "description": "Tenant-level authentication policy settings",
        "endpoints": {
            "getFirstFactorPolicyConfig": {
                "method": "GET",
                "path": "/v1.0/config/firstfactorpolicy",
                "description": "Get first-factor authentication policy configuration",
                "params": {},
                "body": {},
            },
        },
    },

    "Attributes": {
        "description": "Custom attribute configuration for identity data",
        "endpoints": {
            "listAttributes": {
                "method": "GET",
                "path": "/v1.0/attributefunctions",
                "description": "Get all attribute functions",
                "params": {},
                "body": {},
            },
            "evaluateAttribute": {
                "method": "POST",
                "path": "/v2.0/attributequery",
                "description": "Evaluate attribute values",
                "params": {},
                "body": {},
            },
        },
    },

    # ──────────────────────────────────────────────────────────────────
    #  MFA CONFIGURATION
    # ──────────────────────────────────────────────────────────────────

    "Email OTP Configuration 2.0": {
        "description": "Configure email OTP method settings",
        "endpoints": {
            "getEmailOTPConfig": {
                "method": "GET",
                "path": "/v2.0/factors/emailotp/config",
                "description": "Get email OTP configuration",
                "params": {},
                "body": {},
            },
            "updateEmailOTPConfig": {
                "method": "PUT",
                "path": "/v2.0/factors/emailotp/config",
                "description": "Update email OTP configuration",
                "params": {},
                "body": {},
            },
        },
    },

    "SMS OTP Configuration 2.0": {
        "description": "Configure SMS OTP method settings",
        "endpoints": {
            "getSMSOTPConfig": {
                "method": "GET",
                "path": "/v2.0/factors/smsotp/config",
                "description": "Get SMS OTP configuration",
                "params": {},
                "body": {},
            },
            "updateSMSOTPConfig": {
                "method": "PUT",
                "path": "/v2.0/factors/smsotp/config",
                "description": "Update SMS OTP configuration",
                "params": {},
                "body": {},
            },
        },
    },

    "TOTP Configuration 2.0": {
        "description": "Configure TOTP method settings",
        "endpoints": {
            "getTOTPConfig": {
                "method": "GET",
                "path": "/v2.0/factors/totp/config",
                "description": "Get TOTP configuration",
                "params": {},
                "body": {},
            },
            "updateTOTPConfig": {
                "method": "PUT",
                "path": "/v2.0/factors/totp/config",
                "description": "Update TOTP configuration",
                "params": {},
                "body": {},
            },
        },
    },

    "OTP Configuration 2.0": {
        "description": "General OTP configuration",
        "endpoints": {
            "getOTPConfig": {
                "method": "GET",
                "path": "/v2.0/factors/otp/config",
                "description": "Get OTP configuration",
                "params": {},
                "body": {},
            },
            "updateOTPConfig": {
                "method": "PUT",
                "path": "/v2.0/factors/otp/config",
                "description": "Update OTP configuration",
                "params": {},
                "body": {},
            },
        },
    },

    "Voice OTP Configuration": {
        "description": "Configure voice OTP method settings",
        "endpoints": {
            "getVoiceOTPConfig": {
                "method": "GET",
                "path": "/v2.0/factors/voiceotp/config",
                "description": "Get voice OTP configuration",
                "params": {},
                "body": {},
            },
            "updateVoiceOTPConfig": {
                "method": "PUT",
                "path": "/v2.0/factors/voiceotp/config",
                "description": "Update voice OTP configuration",
                "params": {},
                "body": {},
            },
        },
    },

    "Knowledge Questions Configuration": {
        "description": "Configure knowledge question settings",
        "endpoints": {
            "getKQConfig": {
                "method": "GET",
                "path": "/v2.0/factors/questions/config",
                "description": "Get knowledge questions configuration",
                "params": {},
                "body": {},
            },
            "updateKQConfig": {
                "method": "PUT",
                "path": "/v2.0/factors/questions/config",
                "description": "Update knowledge questions configuration",
                "params": {},
                "body": {},
            },
        },
    },

    "Signature Auth Configuration": {
        "description": "Configure signature authentication settings",
        "endpoints": {
            "getSignatureConfig": {
                "method": "GET",
                "path": "/v2.0/factors/signatures/config",
                "description": "Get signature authentication configuration",
                "params": {},
                "body": {},
            },
            "updateSignatureConfig": {
                "method": "PUT",
                "path": "/v2.0/factors/signatures/config",
                "description": "Update signature authentication configuration",
                "params": {},
                "body": {},
            },
        },
    },

    "FIDO Configuration": {
        "description": "Configure FIDO2/WebAuthn relying party settings",
        "endpoints": {
            "listFIDOConfigs": {
                "method": "GET",
                "path": "/v2.0/factors/fido2/config",
                "description": "List FIDO2 configurations",
                "params": {},
                "body": {},
            },
            "createFIDOConfig": {
                "method": "POST",
                "path": "/v2.0/factors/fido2/config",
                "description": "Create a FIDO2 relying party configuration",
                "params": {},
                "body": {},
            },
            "updateFIDOConfig": {
                "method": "PUT",
                "path": "/v2.0/factors/fido2/config/{id}",
                "description": "Update a FIDO2 configuration",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Config ID"},
                },
                "body": {},
            },
            "deleteFIDOConfig": {
                "method": "DELETE",
                "path": "/v2.0/factors/fido2/config/{id}",
                "description": "Delete a FIDO2 configuration",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Config ID"},
                },
                "body": {},
            },
        },
    },

    "QR Code Login Configuration": {
        "description": "Configure QR code login settings",
        "endpoints": {
            "getQRConfig": {
                "method": "GET",
                "path": "/v2.0/factors/qr/config",
                "description": "Get QR code login configuration",
                "params": {},
                "body": {},
            },
            "updateQRConfig": {
                "method": "PUT",
                "path": "/v2.0/factors/qr/config",
                "description": "Update QR code login configuration",
                "params": {},
                "body": {},
            },
        },
    },

    "Authenticator Clients": {
        "description": "Manage IBM Verify Authenticator client applications",
        "endpoints": {
            "getAuthenticatorClients": {
                "method": "GET",
                "path": "/v1.0/authenticators/clients",
                "description": "Get configured authenticator clients",
                "params": {},
                "body": {},
            },
        },
    },

    "reCAPTCHA Configuration": {
        "description": "reCAPTCHA integration configuration",
        "endpoints": {
            "getRecaptchaConfig": {
                "method": "GET",
                "path": "/config/v1.0/recaptcha",
                "description": "List reCAPTCHA configuration",
                "params": {},
                "body": {},
            },
        },
    },

    # ──────────────────────────────────────────────────────────────────
    #  OPERATIONS & MONITORING
    # ──────────────────────────────────────────────────────────────────

    "Events": {
        "description": "Audit events and activity logs",
        "endpoints": {
            "getEvents": {
                "method": "GET",
                "path": "/v1.0/events",
                "description": "Get all events (audit log)",
                "params": {
                    "range": {"type": "string", "required": False, "description": "Time range filter"},
                    "filter": {"type": "string", "required": False, "description": "Event filter"},
                    "sort_by": {"type": "string", "required": False, "description": "Sort field"},
                    "count": {"type": "integer", "required": False, "description": "Number of results"},
                },
                "body": {},
            },
        },
    },

    "Reports": {
        "description": "Report generation and export",
        "endpoints": {
            "exportReport": {
                "method": "POST",
                "path": "/v1.0/reports/export",
                "description": "Export an asynchronous report job",
                "params": {},
                "body": {},
            },
        },
    },

    "Query Logs": {
        "description": "Query system logs",
        "endpoints": {
            "queryLogs": {
                "method": "POST",
                "path": "/v1.0/logs",
                "description": "Query system logs",
                "params": {},
                "body": {},
            },
        },
    },

    "Webhook Configuration": {
        "description": "Configure event webhook subscriptions",
        "endpoints": {
            "listWebhooks": {
                "method": "GET",
                "path": "/config/v1.0/webhooks",
                "description": "List configured webhooks",
                "params": {},
                "body": {},
            },
            "createWebhook": {
                "method": "POST",
                "path": "/config/v1.0/webhooks",
                "description": "Create a webhook subscription",
                "params": {},
                "body": {},
            },
            "getWebhook": {
                "method": "GET",
                "path": "/config/v1.0/webhooks/{id}",
                "description": "Get a specific webhook",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Webhook ID"},
                },
                "body": {},
            },
            "updateWebhook": {
                "method": "PUT",
                "path": "/config/v1.0/webhooks/{id}",
                "description": "Update a webhook",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Webhook ID"},
                },
                "body": {},
            },
            "deleteWebhook": {
                "method": "DELETE",
                "path": "/config/v1.0/webhooks/{id}",
                "description": "Delete a webhook",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Webhook ID"},
                },
                "body": {},
            },
        },
    },

    "Threat Insights Configuration": {
        "description": "ITDR — Identity Threat Detection and Response configuration",
        "endpoints": {
            "getThreatInsightsConfig": {
                "method": "GET",
                "path": "/v1.0/itdr/configurations/default",
                "description": "Get threat insights default configuration",
                "params": {},
                "body": {},
            },
            "updateThreatInsightsConfig": {
                "method": "PUT",
                "path": "/v1.0/itdr/configurations/default",
                "description": "Update threat insights configuration",
                "params": {},
                "body": {},
            },
        },
    },

    # ──────────────────────────────────────────────────────────────────
    #  GOVERNANCE & CERTIFICATION
    # ──────────────────────────────────────────────────────────────────

    "Certification Campaign Configurations v2.0": {
        "description": "Access certification campaign configuration",
        "endpoints": {
            "listCampaignConfigs": {
                "method": "GET",
                "path": "/v2.0/campaigns",
                "description": "List certification campaign configurations",
                "params": {},
                "body": {},
            },
            "getCampaignConfig": {
                "method": "GET",
                "path": "/v2.0/campaigns/{id}",
                "description": "Get a specific campaign configuration",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Campaign config ID"},
                },
                "body": {},
            },
        },
    },

    "Certification Campaign Instances v2.0": {
        "description": "Running certification campaign instances",
        "endpoints": {
            "listCampaignInstances": {
                "method": "GET",
                "path": "/v2.0/instances",
                "description": "List campaign instances",
                "params": {},
                "body": {},
            },
        },
    },

    "Certification Campaign Assignments v2.0": {
        "description": "Certification campaign review assignments",
        "endpoints": {
            "listCampaignAssignments": {
                "method": "GET",
                "path": "/v2.0/instances/{id}/assignments",
                "description": "List campaign assignments by instance ID",
                "params": {
                    "id": {"type": "string", "required": True, "description": "Campaign instance ID"},
                },
                "body": {},
            },
        },
    },

    "Certification Campaign Statistics v2.0": {
        "description": "Campaign statistics and reporting",
        "endpoints": {
            "getCampaignStats": {
                "method": "GET",
                "path": "/v2.0/instances/{instanceId}/assignments/resources",
                "description": "Get campaign assignment/resource statistics",
                "params": {
                    "instanceId": {"type": "string", "required": True, "description": "Campaign instance ID"},
                },
                "body": {},
            },
        },
    },

    # ──────────────────────────────────────────────────────────────────
    #  OTHER / INFRASTRUCTURE
    # ──────────────────────────────────────────────────────────────────

    "Certificates": {
        "description": "Certificate management",
        "endpoints": {
            "listCertificates": {
                "method": "GET",
                "path": "/v1.0/personalcert",
                "description": "Get personal certificates",
                "params": {},
                "body": {},
            },
        },
    },

    "Push Credentials Management": {
        "description": "Push notification credential configuration (APNS/FCM)",
        "endpoints": {
            "listPushCredentials": {
                "method": "GET",
                "path": "/config/v1.0/push-notification/credentials",
                "description": "Get all push credentials for the tenant",
                "params": {},
                "body": {},
            },
        },
    },

    "Email Suppression List": {
        "description": "Manage email suppression list",
        "endpoints": {
            "getEmailSuppression": {
                "method": "GET",
                "path": "/v1.0/notification/suppression/email/{emailAddress}",
                "description": "Get email suppression list",
                "params": {
                    "emailAddress": {"type": "string", "required": True, "description": "Email address to check suppression for"},
                },
                "body": {},
            },
        },
    },

    "Password Vault Configuration": {
        "description": "Password vault settings",
        "endpoints": {
            "getPasswordVaultConfig": {
                "method": "GET",
                "path": "/v1.0/pwdvault/config",
                "description": "Get password vault configuration",
                "params": {},
                "body": {},
            },
        },
    },

    "Password Vault": {
        "description": "Password vault enrollments",
        "endpoints": {
            "getPasswordVaultEnrollment": {
                "method": "GET",
                "path": "/v1.0/pwdvault/enrollments",
                "description": "Get password vault enrollments",
                "params": {},
                "body": {},
            },
        },
    },

    "Admin Entitlement Management": {
        "description": "Manage admin-level entitlements",
        "endpoints": {
            "createAdminEntitlement": {
                "method": "POST",
                "path": "/v1.0/admin/entitlements",
                "description": "Create an admin entitlement",
                "params": {},
                "body": {},
            },
            "listAdminEntitlements": {
                "method": "GET",
                "path": "/v1.0/admin/entitlements",
                "description": "List admin entitlements",
                "params": {},
                "body": {},
            },
        },
    },

    "Template File Registration": {
        "description": "Email/notification template management",
        "endpoints": {
            "getTemplates": {
                "method": "GET",
                "path": "/v1.0/templates",
                "description": "Get tenant-based template registrations by type",
                "params": {
                    "type": {"type": "string", "required": False, "description": "Template type"},
                },
                "body": {},
            },
        },
    },

    "Customization - Themes": {
        "description": "Branding and theme customization",
        "endpoints": {
            "resetTheme": {
                "method": "POST",
                "path": "/v1.0/branding/reset",
                "description": "Reset customizations to default",
                "params": {},
                "body": {},
            },
        },
    },

    "Adapter Management": {
        "description": "Manage adapters (cloud connectors)",
        "endpoints": {
            "listAdapters": {
                "method": "GET",
                "path": "/config/v1.0/profiles",
                "description": "Get adapter profiles",
                "params": {},
                "body": {},
            },
        },
    },

    "Provisioning Management": {
        "description": "Automated provisioning policies",
        "endpoints": {
            "findProvisioningPolicy": {
                "method": "GET",
                "path": "/v1.0/prov/policy/{application}",
                "description": "Find provisioning policies",
                "params": {
                    "application": {"type": "string", "required": True, "description": "Application ID"},
                },
                "body": {},
            },
        },
    },

    "Agent Bridge Support": {
        "description": "On-premises agent bridge management",
        "endpoints": {
            "listOnPremAgents": {
                "method": "GET",
                "path": "/v1.0/agentbridge/agents",
                "description": "List on-premises agents",
                "params": {},
                "body": {},
            },
        },
    },

    "Session Exchange Configuration": {
        "description": "Session exchange configuration settings",
        "endpoints": {
            "getSessionExchangeConfig": {
                "method": "GET",
                "path": "/v1.0/config/sessionexchange",
                "description": "Get session exchange configuration",
                "params": {},
                "body": {},
            },
        },
    },

    "Flow Management": {
        "description": "Manage identity orchestration flows",
        "endpoints": {
            "listFlowModels": {
                "method": "GET",
                "path": "/v1.0/config/models",
                "description": "List flow models",
                "params": {},
                "body": {},
            },
        },
    },

    "External MFA Providers": {
        "description": "External MFA provider integration",
        "endpoints": {
            "listMFAProviders": {
                "method": "GET",
                "path": "/v1.0/mfaproviders",
                "description": "List external MFA provider configurations",
                "params": {},
                "body": {},
            },
        },
    },

    "Device Manager Configuration": {
        "description": "Device management settings",
        "endpoints": {
            "listDeviceManagers": {
                "method": "GET",
                "path": "/config/v1.0/mdm/device-managers",
                "description": "List device manager configurations",
                "params": {},
                "body": {},
            },
        },
    },

    "Smartcard / X.509 Configuration": {
        "description": "Smartcard and X.509 certificate provider settings",
        "endpoints": {
            "listSmartcardProviders": {
                "method": "GET",
                "path": "/config/v1.0/smartcard-providers",
                "description": "List smartcard and X.509 certificate providers",
                "params": {},
                "body": {},
            },
        },
    },

    "Smartcard / X.509 Operations": {
        "description": "Smartcard and certificate provider runtime operations",
        "endpoints": {
            "deleteSmartcardDevice": {
                "method": "DELETE",
                "path": "/config/v1.0/smartcard-providers/{providerId}/devices/{deviceId}",
                "description": "Delete a smartcard/certificate device",
                "params": {
                    "providerId": {"type": "string", "required": True, "description": "Provider ID"},
                    "deviceId": {"type": "string", "required": True, "description": "Device ID"},
                },
                "body": {},
            },
        },
    },

    "Well-Known URIs": {
        "description": "Well-known URI management (Apple/Android app association)",
        "endpoints": {
            "setAppSiteAssociation": {
                "method": "PUT",
                "path": "/.well-known/apple-app-site-association",
                "description": "Set the Apple app site association file",
                "params": {},
                "body": {},
            },
        },
    },
}


# ══════════════════════════════════════════════════════════════════════
#  DISCOVERY ENGINE
# ══════════════════════════════════════════════════════════════════════


class VerifyDiscovery:
    """Index and search the hardcoded Verify API schema."""

    def __init__(self) -> None:
        self._endpoints: dict[str, VerifyEndpoint] = {}
        self._categories: dict[str, int] = {}
        self._build_index()

    def _build_index(self) -> None:
        """Build a flat index of all endpoints from the nested schema."""
        for cat_name, cat_data in VERIFY_API_SCHEMA.items():
            endpoints = cat_data.get("endpoints", {})
            self._categories[cat_name] = len(endpoints)
            for ep_id, ep_data in endpoints.items():
                self._endpoints[ep_id] = VerifyEndpoint(
                    endpoint_id=ep_id,
                    category=cat_name,
                    method=ep_data["method"],
                    path=ep_data["path"],
                    description=ep_data["description"],
                    params=ep_data.get("params", {}),
                    body=ep_data.get("body", {}),
                )
        logger.info(
            "Verify API schema indexed: %d endpoints across %d categories",
            len(self._endpoints),
            len(self._categories),
        )

    @property
    def endpoints(self) -> dict[str, VerifyEndpoint]:
        return self._endpoints

    @property
    def categories(self) -> dict[str, int]:
        return self._categories

    @property
    def total_endpoints(self) -> int:
        return len(self._endpoints)

    def search(
        self,
        query: str,
        category: str | None = None,
        method: str | None = None,
    ) -> list[VerifyEndpoint]:
        """Search endpoints by keyword, optionally filtered by category and method.

        Results are ranked by relevance:
          - Score 4: exact endpoint_id match
          - Score 3: query matches a whole word in endpoint_id
          - Score 2: query matches a whole word in path or description
          - Score 1: substring match anywhere
        """
        import re

        query_lower = query.lower()
        word_pattern = re.compile(r'\b' + re.escape(query_lower) + r'\b', re.IGNORECASE)
        scored: list[tuple[int, VerifyEndpoint]] = []

        for ep in self._endpoints.values():
            # Category filter
            if category and category.lower() not in ep.category.lower():
                continue
            # Method filter
            if method and method.upper() != ep.method:
                continue

            # Relevance scoring
            score = 0
            if query_lower == ep.endpoint_id.lower():
                score = 4  # exact id match
            elif word_pattern.search(ep.endpoint_id):
                score = 3  # whole-word match in id
            elif word_pattern.search(ep.path) or word_pattern.search(ep.description):
                score = 2  # whole-word match in path/description
            else:
                searchable = f"{ep.endpoint_id} {ep.path} {ep.description} {ep.category}".lower()
                if query_lower in searchable:
                    score = 1  # substring match

            if score > 0:
                scored.append((score, ep))

        # Sort by score descending, then by endpoint_id for stability
        scored.sort(key=lambda x: (-x[0], x[1].endpoint_id))
        return [ep for _, ep in scored]

    def get_endpoint(self, endpoint_id: str) -> VerifyEndpoint | None:
        """Get a specific endpoint by its ID."""
        return self._endpoints.get(endpoint_id)
