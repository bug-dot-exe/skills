---
name: api_security_playbook
description: Focused assessment of REST/GraphQL APIs for common vulnerabilities
license: Apache-2.0 (lifted from Armur-Ai/Pentest-Swarm-AI ebca218f :: playbooks/api-security.yaml)
depends_on: []
---

# API Security Assessment

> Phase-orchestrated playbook converted from upstream YAML at
> `Armur-Ai/Pentest-Swarm-AI/playbooks/api-security.yaml` (Apache-2.0).

## Description

Focused assessment of REST/GraphQL APIs for common vulnerabilities

## Variables (declare at scan start)

```yaml
  target_domain:
    type: string
    required: true
  api_base_path:
    type: string
    default: /api

```

## Phases

```yaml
  - name: api_discovery
    tools:
      - name: katana
        options: { depth: 5, js_crawl: true }
      - name: gau
      - name: httpx
        options: { follow_redirects: true }
    post_analysis: |
      Discover all API endpoints. Look for OpenAPI/Swagger docs,
      GraphQL introspection endpoints, versioned APIs, and undocumented
      endpoints in JavaScript bundles.

  - name: api_vulnerabilities
    tools:
      - name: nuclei
        options:
          templates: ["http/vulnerabilities/", "http/misconfiguration/"]
          severity: [critical, high, medium]
    post_analysis: |
      Test for: broken authentication, BOLA/IDOR, mass assignment,
      rate limiting bypass, JWT vulnerabilities, SSRF via API parameters,
      GraphQL injection, and excessive data exposure.
```

## How to use this playbook in bug.exe

1. The phases above are a recommended **execution sequence**. The root agent
   should treat each phase as a worker brief: dispatch a specialist that owns
   that phase's tools, then collect results before progressing.
2. Where the source YAML declares `post_analysis:`, that is the LLM analysis
   prompt for the agent that finishes the phase — pass it through to the
   worker as the `<test_plan>` or `<post_analysis>` portion of the brief.
3. Where the YAML declares `pheromone >= N` gating, treat N as the minimum
   confidence score before escalating to active testing. bug.exe's
   verification ladder is a natural place to enforce this gate.
4. The full original YAML structure is preserved above for reference. If
   bug.exe later adds a native YAML playbook executor, point it at this
   file; otherwise, the agent reads the markdown and dispatches manually.

## Corpus-Derived API Hunting Patterns

Distilled from 1,798 disclosed reports ($19M in bounties). Apply these during
the `api_vulnerabilities` phase alongside nuclei scanning.

### Alternate-Surface Authorization Audit

Multi-surface platforms expose the same data through multiple APIs (mobile,
web, internal RPC, partner, legacy). For every protected resource:

1. List all API surfaces that can access the resource (REST, GraphQL, gRPC,
   SOAP, legacy XML-RPC, mobile-specific endpoints)
2. For each surface, test whether the same authorization check is enforced
3. Focus on internal-service-name endpoints -- any RPC bridge that proxies
   to internal services often skips per-resource ACLs

### Field Mask / Projection Exploitation

When a server-side response is shaped by a client-supplied mask (`fields=`,
`$select=`, projection parameter):

1. Send a request with no mask -- capture the full response schema
2. Add fields not visible in the UI (`internal_*`, `admin_*`, `secret_*`,
   `private_*`, `debug_*`)
3. Test wildcard projections (`fields=*`, `$select=*`)
4. Check if removing the mask returns hidden fields by default

### Search-vs-Direct ACL Split

For any platform with both "list/search/filter" and "direct read" endpoints
for the same data:

1. Create a resource with restricted permissions
2. Confirm the search endpoint respects the ACL (resource not in results)
3. Test the direct-read endpoint with the resource ID -- many implementations
   only filter search results, not direct access

### Cross-Product Bulk Export Paths

When Product A holds resources with stricter ACLs than the surrounding
platform:

1. Find every bulk-export, backup, or transfer feature that crosses product
   boundaries
2. Test whether the export path enforces the source product's ACLs or only
   the platform-level ACLs

### Multi-Auth-Mechanism Testing

For any service supporting multiple authentication methods (cookie, bearer,
mTLS, basic auth, signed request, JWT, API key):

1. Enumerate every auth path
2. Test each endpoint with every auth mechanism -- CSRF protections often
   only apply to one mechanism
3. Mix mechanisms: send cookie + bearer simultaneously, test which takes
   precedence

### Client-Side Path Traversal (CSPT)

Any URL-bar parameter that becomes a path segment in a same-origin API call
is a CSPT candidate:

1. Identify all parameters that feed into fetch/XHR URL construction
2. Inject path traversal sequences (`../`, `..%2F`, `..%252F`)
3. Check if the traversal redirects the API call to a different endpoint
   on the same origin

### API Gateway / Proxy Layer Differential

Any tier in front of multiple origins (CDN, load balancer, API gateway,
reverse proxy) parses HTTP differently than the backend:

1. Test bare CR (`\r` without `\n`), bare LF, null bytes in headers
2. Test `Transfer-Encoding` vs `Content-Length` conflicts
3. Test HTTP/2 downgrade behavior to HTTP/1.1 backends
4. Test chunk-size extensions and trailing headers

### Disabled UI Elements Are Not Access Controls

When a UI disables a button or hides a feature based on permissions:

1. Remove the `disabled` attribute, click, and observe the request
2. Replay the request directly -- if it succeeds, the UI was the only gate
3. Check PATCH/PUT endpoints for mass-assignment of role/permission fields

### OAuth Scope Enumeration

For any OAuth provider with many scopes:

1. Enumerate ALL API capabilities of each scope by calling every endpoint
   with a token that has only that scope
2. Test scope inheritance -- does `read` scope also grant `list`?
3. Test scope combination -- do two low-privilege scopes combine to grant
   unintended access?

### JSONP / postMessage Proxy Audit

Most major platforms have proxy iframes that bridge first-party APIs to
third-party sites:

1. List all `proxy.html`, `callback.html`, `relay.html` files
2. For each, test whether the origin check is bypassable (wildcard,
   regex bypass, null origin)
3. Test JSONP callbacks for XSS via callback parameter injection

---

**Source attribution**: This playbook is a faithful conversion of the
Apache-2.0-licensed YAML at upstream Armur-Ai/Pentest-Swarm-AI. The phase
structure and post_analysis text are reproduced verbatim. See
`bugdotexe/skills/playbooks/SOURCE.md` for full provenance.
