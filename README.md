# APISIX AuthZEN Plugin

An [Apache APISIX](https://apisix.apache.org/) plugin that implements the [AuthZEN](https://openid.net/specs/openid-authzen-authorization-api-1_0-ID1.html) authorization API standard, enabling standardized policy-based access control through any AuthZEN-compliant Policy Decision Point (PDP).

## Overview

### Main Features

This development transforms Apache APISIX into an **AuthZEN-compliant PEP**, externalizing authorization decisions to any AuthZEN-compatible PDP. This approach:

- **Secures AI/MCP tool calls** - Authorize Model Context Protocol (MCP) requests with fine-grained access control
- **Centralizes decision-making** - Easier to manage and update policies across all applications
- **Decouples authorization from code** - Improves security, flexibility, and maintainability
- **Enables scalability** - Consistent enforcement across all protected resources

- **AuthZEN-compliant PEP** — Delegates authorization decisions to any AuthZEN-compatible PDP for APIs and MCP requests
- **JWT-Based Subject Identification** — Extracts subject identity dynamically from JWT claims (e.g., `sub`, `preferred_username`)
- **Dynamic JWT Context Extraction** — Maps JWT claims into AuthZEN `subject.properties` for attribute-based and relationship-based authorization
- **Dynamic Resource & Action Mapping** — Builds AuthZEN resource identifiers from request URI, static values, or MCP context; maps HTTP methods or MCP tool arguments to actions
- **Authenticated PDP Calls** — Supports static API keys and OAuth2 `client_credentials` for gateway→PDP authentication, with automatic token caching and renewal
- **MCP-Aware Policy Enforcement** — Understands MCP JSON-RPC requests; enforces per-tool authorization with selective enforcement on specific methods
- **OIDC/OAuth Integration** — Works alongside the APISIX OIDC plugin; assumes tokens are validated upstream before authorization


### Tested PDP Backends

- **OpenFGA** - Relationship-based access control (ReBAC)
- **Cerbos** - Policy-based access control (PBAC)
- **Keycloak** - Resource-based policies authorization

Should be compatible with **Any AuthZEN-compliant PDP**.

### Why AuthZEN?

Access control failures are the #1 security risk in the [OWASP Top 10 (2021)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/). Traditional authorization approaches suffer from:

- **Lack of Interoperability** - Custom implementations lead to high maintenance costs
- **Authorization Complexity** - Traditional models are hard to scale
- **Tight Coupling** - Authorization logic embedded in application code reduces flexibility

The [OpenID Foundation AuthZEN Working Group](https://openid.net/wg/authzen/) addresses these challenges by standardizing authorization interactions based on the **P\*P architecture** principles, enabling interoperability between Policy Enforcement Points (PEP) and Policy Decision Points (PDP).


## Architecture

### Components Overview

```
                          ┌────────────────────────────────────────────────────────────┐
                          │                      Authorization                         │
                          │    ┌─────────────────┐                                     │
                          │    │   AuthZEN PDP   │                                     │
                          │    │                 │                                     │ 
                          │    └─────┬───────────┘                                     │    
                          │          │                                                 │
                       evaluation()  │  result { decision: true/false }                │
                          │          │                                                 │
                          │          │                                                 │
                          │          ▼                                                 │
┌──────────┐              │    ┌─────────────────┐                    ┌───────────┐    │
│          │   Request    │    │                 │     Request        │           │    │
│   Apps   │ ──────────────►   │  API/AI Gateway │ ─────────────────► │  API/MCP  │    │
│          │              │    │  (AuthZEN PEP)  │                    │           │    │
└──────────┘              │    └─────────────────┘                    └───────────┘    │
                          │         APISIX                                             │
                          └────────────────────────────────────────────────────────────┘
```

**AuthZEN Request (PEP → PDP):**
```json
{
  "subject":  { "type": "...", "id": "..." , "properties" :  {} },
  "resource": { "type": "...", "id": "...", "properties" :  {} } ,
  "action":   { "name": "..." },
  "context" : { }
}
```

**AuthZEN Response (PDP → PEP):**
```json
{
  "decision": true
}
```

### Sequence Diagram

```mermaid
sequenceDiagram
    participant App
    participant PEP as API / AI Gateway <br/> (AuthZEN PEP)
    participant PDP as AuthZEN PDP
    participant API as API / MCP

    App->>PEP: Sends API request
    PEP->>PEP: Authenticate Request
    PEP->>PEP: Extract details (subject, method, resource)
    PEP->>PDP: Sends AuthZEN request
    PDP->>PDP: Evaluates policy
    PDP-->>PEP: Returns allow/deny decision

    alt Allow
        PEP->>API: Forwards request
        API-->>PEP: Returns response
        PEP-->>App: Returns response
    else Deny
        PEP-->>App: Returns 403 Forbidden
    end
```

## Gateway AuthZEN Configuration

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| **pdp** | object | Yes | | PDP configuration |
| pdp.host | string | Yes | | PDP base URL (e.g., `https://pdp.example.com`) |
| pdp.platform | string | No | `default` | Platform type: `default`, `openfga`, `cerbos` |
| pdp.model | string | No | `discover` | For OpenFGA: `discover` to auto-discover store_id, or specify store_id directly |
| **pdp.auth** | object | No | | PDP authentication configuration |
| pdp.auth.api_key | string | No | | Static API key sent as `Authorization` header (mutually exclusive with `oauth2`) |
| pdp.auth.oauth2 | object | No | | OAuth2 `client_credentials` config for gateway→PDP auth (mutually exclusive with `api_key`) |
| pdp.auth.oauth2.token_url | string | Yes* | | Token endpoint URL (e.g., Keycloak token endpoint) |
| pdp.auth.oauth2.client_id | string | Yes* | | OAuth2 client ID |
| pdp.auth.oauth2.client_secret | string | Yes* | | OAuth2 client secret (encrypted at rest) |
| pdp.auth.oauth2.scopes | array | No | | Requested token scopes (space-joined) |
| **http** | object | No | | HTTP client configuration |
| http.timeout | integer | No | `3000` | Request timeout in milliseconds (1-60000) |
| http.ssl_verify | boolean | No | `false` | Enable SSL certificate verification |
| http.keepalive | boolean | No | `true` | Enable HTTP keepalive connections |
| http.keepalive_timeout | integer | No | `60000` | Keepalive timeout in milliseconds |
| http.keepalive_pool | integer | No | `5` | Keepalive connection pool size |
| **subject** | object | No | | Subject configuration for AuthZEN request |
| subject.type | string | No | `identity` | Subject type in AuthZEN request |
| subject.id | string | No | `claim::sub` | Subject ID source (see [Value Extraction Syntax](#value-extraction-syntax)) |
| subject.properties | array | No | | Array of JWT claim mappings to subject properties |
| **resource** | object | No | | Resource configuration for AuthZEN request |
| resource.type | string | No | `route` | Resource type in AuthZEN request |
| resource.id | string | No | `uri` | Resource ID source (see [Value Extraction Syntax](#value-extraction-syntax)) |
| **action** | object | No | | Action configuration for AuthZEN request |
| action.name | string | No | `method` | Action name source: `method` for HTTP method (see [Value Extraction Syntax](#value-extraction-syntax)) |
| **mcp** | object | No | | MCP (Model Context Protocol) configuration |
| mcp.enforce_on | object | No | | Selective enforcement configuration |
| mcp.enforce_on.methods | array | No | `[]` | MCP JSON-RPC methods to enforce authorization on (e.g., `["tools/call"]`). If empty, all requests are enforced. |

### Subject Properties Schema

Each item in `subject.properties` array:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| key | string | Yes | Property name in AuthZEN request |
| claim | string | Yes | JWT claim path (e.g., `realm_access.roles`, `tenant`) |


### Value Extraction Syntax

The `subject.id`, `resource.id`, and `action.name` fields support dynamic value extraction using the following syntax:

| Syntax | Source | Example |
|--------|--------|---------|
| `claim::<name>` | JWT claim | `claim::sub`, `claim::preferred_username` |
| `mcp::tool::name` | MCP tool name from JSON-RPC body | Tool name from `params.name` |
| `mcp::tool::arguments::<arg>` | MCP tool argument | `mcp::tool::arguments::tenant` |
| `uri` | HTTP request URI | `/api/v1/products` |
| `method` | HTTP method | `GET`, `POST` |
| (static value) | Literal string | `user`, `document`, `read` |


> **IMPORTANT:** This plugin assumes a valid JWT. You must configure the APISIX OIDC plugin with higher priority to validate the token before AuthZEN authorization is evaluated.

## AuthZEN Request Format

The plugin constructs AuthZEN-compliant requests following the specification:

```json
{
  "subject": {
    "type": "<subject_type>",
    "id": "<subject_identifier>",
    "properties": {
      "<key>": "<claim-value>"
    }
  },
  "resource": {
    "type": "<resource_type>",
    "id": "<resource_identifier>"
  },
  "action": {
    "name": "<action_name>"
  }
}
```

## AuthZEN Response Format

The plugin expects a standard AuthZEN response:

```json
{
  "decision": true
}
```

| Response | HTTP Status | Description |
|----------|-------------|-------------|
| `decision: true` | Request proceeds | Access granted |
| `decision: false` | 403 Forbidden | Access denied |
| PDP unavailable | 503 Service Unavailable | Authorization service error |
| Missing JWT claim | 401 Unauthorized | Required claim not found |


## Considerations

> [!CAUTION]
> **Beta Software Notice: This software is currently in beta and is provided AS IS without any warranties.**
>
> - Not recommended for production use
> - Issues and feedback should be reported via the GitHub issue tracker
> - Maintenance and response times are best-effort
>
> By using this beta software, you acknowledge and accept these conditions.

## Examples

<details>
<summary><strong>Example 1: Default Platform (Gateway Profile)</strong></summary>

Minimal configuration using defaults - ideal for standard AuthZEN PDPs:

```json
{
  "pdp": {
    "host": "https://pdp.example.com"
  }
}
```

This uses the default AuthZEN Gateway Profile:
- **Subject**: `type: "identity"`, `id: <JWT sub claim>`
- **Resource**: `type: "route"`, `id: <request URI>`
- **Action**: `name: <HTTP method>`

**AuthZEN request sent to PDP:**

```json
{
  "subject": {
    "type": "identity",
    "id": "214cc559-1bd1-4436-ab82-621f3a414b34"
  },
  "resource": {
    "type": "route",
    "id": "/api/protected"
  },
  "action": {
    "name": "GET"
  }
}
```

</details>

<details>
<summary><strong>Example 2: OpenFGA with Auto-Discovery</strong></summary>

For OpenFGA with automatic store_id discovery:

```json
{
  "pdp": {
    "host": "http://localhost:8080",
    "platform": "openfga",
    "model": "discover"
  }
}
```

The plugin will:
1. Call `GET {host}/stores` to discover available stores
2. Use the first store's ID
3. Cache the store_id for subsequent requests
4. Send requests to: `POST {host}/stores/{store_id}/access/v1/evaluation`

</details>

<details>
<summary><strong>Example 3: OpenFGA with Explicit Store ID</strong></summary>

Skip discovery by specifying the store_id directly:

```json
{
  "pdp": {
    "host": "http://localhost:8080",
    "platform": "openfga",
    "model": "01JNW1803442023HVDKV03FB3A"
  }
}
```

**Endpoint used:** `POST http://localhost:8080/stores/01JNW1803442023HVDKV03FB3A/access/v1/evaluation`

</details>

<details>
<summary><strong>Example 4: Cerbos with Subject Properties</strong></summary>

Include JWT claims as subject properties for attribute-based decisions:

```json
{
  "pdp": {
    "host": "http://localhost:3593",
    "platform": "cerbos"
  },
  "subject": {
    "type": "user",
    "id": "claim::sub",
    "properties": [
      { "key": "roles", "claim": "realm_access.roles" },
      { "key": "tenant", "claim": "tenant" },
      { "key": "email", "claim": "email" }
    ]
  },
  "resource": {
    "type": "document",
    "id": "uri"
  },
  "action": {
    "name": "method"
  }
}
```

**AuthZEN request sent to PDP:**

```json
{
  "subject": {
    "type": "user",
    "id": "214cc559-1bd1-4436-ab82-621f3a414b34",
    "properties": {
      "roles": ["admin", "user"],
      "tenant": "acme",
      "email": "admin@example.com"
    }
  },
  "resource": {
    "type": "document",
    "id": "/api/documents/123"
  },
  "action": {
    "name": "GET"
  }
}
```

</details>

<details>
<summary><strong>Example 5: With Static API Key and HTTP Settings</strong></summary>

For PDPs requiring authentication with a static API key:

```json
{
  "pdp": {
    "host": "https://pdp.example.com",
    "platform": "default",
    "auth": {
      "api_key": "Bearer your-api-key-here"
    }
  },
  "http": {
    "timeout": 5000,
    "ssl_verify": true,
    "keepalive": true,
    "keepalive_timeout": 60000,
    "keepalive_pool": 10
  }
}
```
</details>

<details>
<summary><strong>Example 6: MCP Tool Authorization</strong></summary>

Authorize AI/MCP tool calls:

**Plugin Configuration:**
```json
{
  "pdp": {
    "host": "http://localhost:8080",
  },
  "subject": {
    "type": "user",
    "id": "claim::sub"
  },
  "resource": {
    "type": "tool",
    "id": "mcp::tool::name"
  },
  "action": {
    "name": "execute"
  }
}
```

**MCP Request Body:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "fintech_list_expenses",
    "arguments": {
      "tenant": "tenant1"
    }
  }
}
```

**AuthZEN request sent to PDP:**
```json
{
  "subject": {
    "type": "user",
    "id": "214cc559-1bd1-4436-ab82-621f3a414b34"
  },
  "resource": {
    "type": "tool",
    "id": "fintech_list_expenses"
  },
  "action": {
    "name": "execute"
  }
}
```

</details>

<details>
<summary><strong>Example 7: MCP Selective Enforcement (Only tools/call)</strong></summary>

Enforce authorization only for `tools/call` requests, allowing other MCP methods like `initialize` and `tools/list` to pass through without authorization:

**Plugin Configuration:**
```json
{
  "pdp": {
    "host": "http://localhost:8080",
  },
  "mcp": {
    "enforce_on": {
      "methods": ["tools/call"]
    }
  },
  "subject": {
    "type": "user",
    "id": "claim::sub"
  },
  "resource": {
    "type": "mcp",
    "id": "bank"
  },
  "action": {
    "name": "mcp::tool::name"
  }
}
```

**Behavior:**

| MCP Method | Authorization |
|------------|---------------|
| `tools/call` | Enforced |
| `initialize` | Skipped (allowed) |
| `tools/list` | Skipped (allowed) |
| `resources/list` | Skipped (allowed) |

**MCP Request (tools/call - enforced):**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "fintech_list_expenses",
    "arguments": { "tenant": "tenant1" }
  }
}
```
→ Authorization check performed, AuthZEN request sent to PDP

**MCP Request (initialize - skipped):**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {}
  }
}
```
→ Request passes through without authorization

**Note:** If the `mcp.enforce_on` configuration is not provided or `methods` is empty, all requests are enforced (backward compatible behavior).
</details>

<details>
<summary><strong>Example 8: Keycloak Authorization Services as PDP (OAuth2 PDP Auth)</strong></summary>

Use Keycloak's built-in AuthZEN endpoint (`KC_FEATURES=authzen`) as the PDP. The gateway authenticates to Keycloak using OAuth2 `client_credentials` — the token is fetched once, cached, and renewed automatically before expiry.

**Prerequisites:**
- Keycloak started with `KC_FEATURES=authzen`
- A dedicated gateway client (`gateway-client`) with `authorizationServicesEnabled=true` and the relevant resources/policies configured

```json
{
  "pdp": {
    "host": "http://keycloak:8080/realms/demo/authzen",
    "auth": {
      "oauth2": {
        "token_url": "http://keycloak:8080/realms/demo/protocol/openid-connect/token",
        "client_id": "gateway-client",
        "client_secret": "gateway-secret"
      }
    }
  },
  "subject": {
    "type": "user",
    "id": "claim::preferred_username"
  },
  "resource": {
    "id": "todo-1",
    "type": "todo"
  },
  "action": {
    "name": "can_read_todos"
  }
}
```

**How it works:**
1. On first request, the plugin calls Keycloak's token endpoint with `grant_type=client_credentials`
2. The resulting access token is cached (TTL = `expires_in - 10s`) in the shared APISIX memory store
3. Subsequent requests reuse the cached token; it is refreshed automatically when the cache expires
4. If token renewal fails (e.g., client disabled), APISIX returns `503 Service Unavailable`
5. Keycloak evaluates the AuthZEN request against the policies defined in `gateway-client`'s Authorization Services

</details>

## References

- [AuthZEN Specification](https://openid.net/specs/openid-authzen-authorization-api-1_0-ID1.html)
- [OpenID Foundation AuthZEN Working Group](https://openid.net/wg/authzen/)
- [OpenFGA](https://openfga.dev/)
- [Cerbos](https://cerbos.dev/)
- [Apache APISIX](https://apisix.apache.org/)

## Commercial Support

Enterprise support, SLAs, and commercial features are available via [TwoGenIdentity](https://twogenidentity.com).
Originally designed and implemented by [Martin Besozzi](https://github.com/embesozzi). Maintained under the [TwoGenIdentity](https://github.com/TwoGenIdentity) organization.

Copyright 2026 TwoGenIdentity. All Rights Reserved.
