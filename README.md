# APISIX AuthZEN Plugin

An [Apache APISIX](https://apisix.apache.org/) plugin that implements the [AuthZEN](https://openid.net/specs/openid-authzen-authorization-api-1_0-ID1.html) authorization API standard, enabling standardized policy-based access control through any AuthZEN-compliant Policy Decision Point (PDP).

> [!CAUTION]
> **Beta Software Notice: This software is currently in beta and is provided AS IS without any warranties.**
>
> - Not recommended for production use
> - Issues and feedback should be reported via the GitHub issue tracker
> - Maintenance and response times are best-effort
>
> By using this beta software, you acknowledge and accept these conditions.

## Overview

### Why AuthZEN?

Access control failures are the #1 security risk in the [OWASP Top 10 (2021)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/). Traditional authorization approaches suffer from:

- **Lack of Interoperability** - Custom implementations lead to high maintenance costs
- **Authorization Complexity** - Traditional models are hard to scale
- **Tight Coupling** - Authorization logic embedded in application code reduces flexibility

The [OpenID Foundation AuthZEN Working Group](https://openid.net/wg/authzen/) addresses these challenges by standardizing authorization interactions based on the **P\*P architecture** principles, enabling interoperability between Policy Enforcement Points (PEP) and Policy Decision Points (PDP).

### What This Plugin Does

This plugin transforms Apache APISIX into an **AuthZEN-compliant PEP**, externalizing authorization decisions to any AuthZEN-compatible PDP. This approach:

- **Centralizes decision-making** - Easier to manage and update policies across all applications
- **Decouples authorization from code** - Improves security, flexibility, and maintainability
- **Enables scalability** - Consistent enforcement across all protected resources

### Tested PDP Backends

- **OpenFGA** - Relationship-based access control (ReBAC)
- **Cerbos** - Policy-based access control (PBAC)

Should be compatible with **Any AuthZEN-compliant PDP**..
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
    participant PEP as API / AI Gateway <br/> (AuthZEN PDP)
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

## Attributes

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| **pdp** | object | Yes | | PDP configuration |
| pdp.host | string | Yes | | PDP base URL (e.g., `https://pdp.example.com`) |
| pdp.platform | string | No | `default` | Platform type: `default`, `openfga`, `cerbos` |
| pdp.model | string | No | `discover` | For OpenFGA: `discover` to auto-discover store_id, or specify store_id directly |
| pdp.api_key | string | No | | API key for PDP authentication (sent as Authorization header) |
| **http** | object | No | | HTTP client configuration |
| http.timeout | integer | No | `3000` | Request timeout in milliseconds (1-60000) |
| http.ssl_verify | boolean | No | `false` | Enable SSL certificate verification |
| http.keepalive | boolean | No | `true` | Enable HTTP keepalive connections |
| http.keepalive_timeout | integer | No | `60000` | Keepalive timeout in milliseconds |
| http.keepalive_pool | integer | No | `5` | Keepalive connection pool size |
| **subject** | object | No | | Subject configuration for AuthZEN request |
| subject.type | string | No | `identity` | Subject type in AuthZEN request |
| subject.id | string | No | `claim::sub` | Subject ID source: `claim::<claim_name>` for JWT claim extraction |
| subject.properties | array | No | | Array of JWT claim mappings to subject properties |
| **resource** | object | No | | Resource configuration for AuthZEN request |
| resource.type | string | No | `route` | Resource type in AuthZEN request |
| resource.id | string | No | `uri` | Resource ID source: `uri` for request URI or static value |
| **action** | object | No | | Action configuration for AuthZEN request |
| action.name | string | No | `method` | Action name source: `method` for HTTP method or static value |

### Subject Properties Schema

Each item in `subject.properties` array:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| key | string | Yes | Property name in AuthZEN request |
| claim | string | Yes | JWT claim path (e.g., `realm_access.roles`, `tenant`) |

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

## Access Flow

1. Client sends API request with JWT bearer token
2. Plugin extracts subject ID from configured JWT claim (default: `sub`)
3. Plugin extracts resource ID from request URI (or configured static value)
4. Plugin extracts action name from HTTP method (or configured static value)
5. Plugin sends AuthZEN evaluation request to PDP
6. PDP returns decision (`true` or `false`)
7. Plugin allows request to proceed or returns 403

> **Important:** This plugin assumes a valid JWT. You must configure the APISIX OIDC plugin with higher priority to validate the token before AuthZEN authorization is evaluated.

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
<summary><strong>Example 5: With API Key and HTTP Settings</strong></summary>

For PDPs requiring authentication with custom HTTP settings:

```json
{
  "pdp": {
    "host": "https://pdp.example.com",
    "platform": "default",
    "api_key": "Bearer your-api-key-here"
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
