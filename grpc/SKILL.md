---
name: grpc
description: gRPC security testing covering reflection enumeration, authentication bypass, message tampering, and metadata injection
depends_on: []
---

# gRPC

Security testing for gRPC services. Focus on server reflection enumeration, authentication and authorization bypass, protobuf message tampering, server-side streaming abuse, and metadata header injection.

## Attack Surface

**Service Definition**
- Protocol Buffer (protobuf) service definitions: methods, message types, enums
- Unary RPCs, server streaming, client streaming, bidirectional streaming
- Service reflection: runtime schema discovery

**Transport**
- HTTP/2 framing (always)
- TLS: mTLS, server-only TLS, or plaintext (insecure channel)
- gRPC-Web: browser-compatible proxy (Envoy, grpc-web)

**Authentication**
- Per-call credentials: metadata headers (Bearer tokens, API keys)
- Channel credentials: TLS certificates, mTLS
- Interceptors: server-side auth interceptors, per-method authorization
- gRPC-Gateway: REST-to-gRPC translation with auth header forwarding

**Metadata**
- Request metadata: key-value pairs sent with every call (like HTTP headers)
- Binary metadata: keys ending in `-bin` carry binary values
- Reserved metadata: `grpc-*` prefixed keys
- Trailing metadata: sent with response

**Common Stacks**
- Go: grpc-go with interceptors
- Java/Kotlin: grpc-java, Spring Boot integration
- Python: grpcio, grpc-tools
- Node.js: @grpc/grpc-js
- .NET: Grpc.Net, Grpc.Core

## High-Value Targets

- Reflection-enabled services in production
- Admin/management service definitions (UserService, AdminService, ConfigService)
- Streaming endpoints handling large data transfers or real-time feeds
- gRPC-Gateway REST endpoints that map to privileged gRPC methods
- Health check services (`grpc.health.v1.Health`)
- Internal service-to-service gRPC endpoints exposed to external networks

## Reconnaissance

**Reflection Enumeration**
```bash
# List all services
grpcurl -plaintext target:50051 list

# Describe a service
grpcurl -plaintext target:50051 describe MyService

# Describe a message type
grpcurl -plaintext target:50051 describe MyService.MyRequest

# List methods of a service
grpcurl -plaintext target:50051 list MyService
```

If reflection is enabled, the entire service schema is discoverable: all services, methods, request/response types, field names, types, and enums. This is equivalent to obtaining the `.proto` files.

**Without Reflection**
- Obtain `.proto` files from: public repositories, client applications, documentation, error messages
- Fuzz common service names: `grpc.health.v1.Health/Check`, `grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo`
- Inspect gRPC-Web traffic in browser developer tools (protobuf messages in network tab)
- Decompile mobile apps for bundled proto definitions

**Service Discovery**
```bash
# Health check
grpcurl -plaintext target:50051 grpc.health.v1.Health/Check

# Try common ports
# 50051 (default), 443 (TLS), 8080 (gRPC-Web), 9090 (common alt)
```

**gRPC-Web Detection**
- `Content-Type: application/grpc-web+proto` or `application/grpc-web-text+proto`
- Envoy proxy with gRPC-Web filter
- `grpc-web` JavaScript library in client bundles

## Key Vulnerabilities

### Reflection Enumeration

**Schema Disclosure**
- Full API surface discoverable without authentication
- Internal service definitions, admin methods, debug endpoints
- Message types reveal database schema, internal data structures
- Enum values expose business logic states and valid values

**Mitigation Check**
- Is reflection disabled in production?
- If enabled: is it restricted to authenticated clients?
- Test both v1alpha and v1 reflection APIs

### Authentication Bypass

**Missing Auth Interceptors**
```bash
# Call method without any credentials
grpcurl -plaintext target:50051 MyService/AdminMethod -d '{}'

# Call with empty/invalid token
grpcurl -plaintext -H 'authorization: Bearer invalid' target:50051 MyService/GetUser -d '{"id": 1}'
```

- Auth enforced on some methods but not others (same service)
- Auth interceptor checks token presence but not validity
- Different auth requirements between unary and streaming methods

**Token Manipulation**
- JWT tokens in metadata: algorithm confusion, expired token acceptance, missing audience/issuer
- API keys in metadata: weak keys, shared keys across environments
- mTLS: client certificate validation incomplete (accepts any valid cert, not checking CN/SAN)

**Interceptor Ordering**
- Auth interceptor registered after logging/metrics interceptors: auth bypass on error paths
- Streaming interceptors: auth checked at stream creation but not per-message
- gRPC-Gateway: REST auth headers not properly forwarded to gRPC metadata

### Authorization Gaps

**Method-Level IDOR**
```bash
# Access another user's data
grpcurl -plaintext -H 'authorization: Bearer USER_TOKEN' \
  target:50051 UserService/GetProfile -d '{"user_id": "OTHER_USER_ID"}'
```

- Object IDs in request messages not validated against caller identity
- Admin methods accessible to regular users (missing role check)
- Service-to-service methods callable by external clients

**Field-Level Authorization**
- Request includes fields the caller should not control (role, permissions, internal flags)
- Response includes sensitive fields regardless of caller authorization level
- Update methods accepting partial messages without field-level permission checks

### Message Tampering

**Protobuf Manipulation**
- Modify field values in serialized protobuf messages
- Add unknown fields (protobuf preserves unknown fields by default)
- Type confusion: send wrong message type for a method (may partially deserialize)

**Default Value Exploitation**
- Protobuf default values: 0 for numbers, empty for strings, false for bools
- Missing fields default silently; server may not distinguish "field not sent" from "field is zero/empty"
- Boolean flags: omitting an `is_admin` field defaults to `false` but omitting `is_restricted` also defaults to `false`

**Oneof Field Abuse**
- `oneof` fields: only one field in the group should be set
- Send multiple fields in a oneof group; behavior varies by implementation
- Set an unexpected variant to bypass validation for the expected variant

### Server-Side Streaming Abuse

**Resource Exhaustion**
- Request unbounded server streams: large result sets, long-lived connections
- Multiple concurrent streams from single client consuming server resources
- Stream without flow control: client stops reading but server keeps sending

**Data Exfiltration via Streams**
- Streaming methods returning paginated data without proper per-page authorization
- Subscribe to event streams with filter parameters that bypass access control
- Bidirectional streams allowing injection of messages into shared channels

### Metadata Injection

**Header Injection**
```bash
# Inject internal routing headers
grpcurl -H 'x-internal-service: true' -H 'x-user-id: admin' \
  target:50051 MyService/Method -d '{}'
```

- Internal metadata headers trusted without validation (x-user-id, x-tenant-id, x-roles)
- gRPC-Gateway forwarding all HTTP headers as metadata
- Binary metadata keys (`-bin` suffix) carrying serialized objects without validation

**Metadata Propagation**
- Service A forwards all metadata to Service B (including attacker-injected headers)
- Trace/correlation headers manipulated to confuse logging and monitoring
- Deadline propagation: set very short deadline to cause timeouts in downstream services

### Plaintext Communication

**No TLS**
- gRPC over plaintext HTTP/2: credentials and data visible to network observers
- Internal services assuming network-level security (no encryption between services)
- gRPC-Web proxy terminating TLS but connecting to backend over plaintext

**Weak TLS**
- Server-only TLS without mTLS: any client can connect
- Expired or self-signed certificates accepted by clients
- Missing hostname verification in client connections

### Error Information Disclosure

**Status Details**
- gRPC status messages and details containing: stack traces, SQL queries, internal paths
- `google.rpc.Status` details with debug_info, error metadata
- Different error codes/messages for valid vs invalid resources (enumeration)

## Bypass Techniques

- Reflection access without auth even when methods require auth (separate service)
- gRPC-Web content-type bypassing WAF rules designed for application/grpc
- Deadline manipulation causing partial processing (auth checked, business logic times out)
- Client streaming: send auth in first message, malicious data in subsequent messages
- Metadata key case sensitivity differences between proxy and server
- HTTP/2 HEADERS frame manipulation for gRPC metadata injection

## Testing Methodology

1. **Service discovery** - Test reflection, enumerate services and methods, obtain proto definitions
2. **Auth testing** - Call each method without credentials, with invalid credentials, with other users' credentials
3. **IDOR probing** - Manipulate object IDs in request messages across different authenticated contexts
4. **Message manipulation** - Modify field values, add unknown fields, test default value behavior
5. **Streaming tests** - Test authorization on streaming methods, resource limits, per-message auth
6. **Metadata injection** - Inject internal headers, test propagation through service chain
7. **Transport security** - Verify TLS enforcement, certificate validation, mTLS requirements
8. **Error analysis** - Collect error responses for information disclosure patterns

## Validation

1. Reflection: full service schema enumerated from production endpoint without authentication
2. Auth bypass: privileged method invoked without valid credentials returning data
3. IDOR: request with modified ID returning another user's data
4. Message tampering: unknown or unauthorized fields accepted and processed by server
5. Metadata injection: internal header accepted and influencing server behavior
6. Streaming abuse: unauthorized data received via streaming method
7. Information disclosure: error response containing stack trace, query, or internal path

## False Positives

- Reflection disabled or restricted to authenticated admin users
- All methods enforce auth via interceptor with proper token validation
- Unknown protobuf fields discarded by strict deserialization
- Metadata sanitized at gateway before forwarding to backend
- Proper mTLS with certificate pinning for all service communication

## Impact

- Full API schema disclosure enabling targeted attacks on all service methods
- Authentication bypass granting access to privileged operations
- Data access via IDOR across all protobuf message types
- Resource exhaustion via unbounded streaming
- Lateral movement via metadata injection in service-to-service calls

## Corpus-Derived Attack Patterns

### Internal-Service-Name RPC Bridge Auth Audit
At any organization with heavy internal-RPC architecture, enumerate internal service names from error messages, reflection output, or client bundles. Test whether internal RPC methods (support tools, admin dashboards, debug endpoints) are accessible from external networks. Internal services frequently skip per-call auth because they assume network-level isolation that does not exist at the load balancer or ingress boundary.

### Identifier-Chain Auditing for IDOR
For any RPC that returns sensitive data gated on identifier `X`: list ALL RPCs that produce `X` as an output, given a different input `Y`. If you can obtain a foreign user's `X` from an unprotected or lower-privilege RPC, you can use it to call the sensitive RPC. Map the full identifier dependency chain: which RPCs produce which IDs, and which RPCs consume them with what authorization checks.

### Multi-Auth-Mechanism CSRF (cookie vs bearer disagreement)
For any service that supports multiple authentication mechanisms (cookie, bearer, mTLS, basic, signed request, JWT): enumerate every auth path and test each one independently. Then test what happens when multiple auth mechanisms are present simultaneously. If cookie-auth is accepted alongside bearer-auth, CSRF attacks via cookie-auth may bypass bearer-token-only CSRF protections.

### Multi-API-Surface Policy Parity Audit
When a platform has multiple API surfaces (REST + gRPC + GraphQL + WebSocket), treat each pair as a policy parity test. Authenticate via one surface, then test whether the same authorization restrictions apply on all others. Deactivated users, suspended accounts, and revoked permissions are commonly enforced on the primary surface but not on the gRPC or WebSocket surface.

### Batch/Multicall Endpoint Rate Limit Bypass
Look for batch or multicall RPC endpoints that let a single request trigger N internal operations. These bypass per-request rate limits, WAF rules, and logging thresholds. Test: (1) brute-force via batched auth attempts, (2) DoS amplification via batched heavy operations, (3) TOCTOU races via batched state-changing operations that execute faster than sequential requests.

### Grammar-Violation Audit for Protobuf Parsers
For any parser with structured grammar (protobuf, ASN.1, Thrift): get the format's grammar/schema, then systematically violate each grammar rule one at a time. Test: (1) missing required fields, (2) wrong wire types for field numbers, (3) varint overflow, (4) nested message depth exceeding limits, (5) truncated messages at each field boundary. Parser crashes and memory corruption are common in C/C++ protobuf implementations.

### Dual-Layer Authorization Parity Testing
When a target has both a web UI and a gRPC API that mirror the same features, treat each pair as a dual-layer authorization test. Actions restricted in the UI may be unrestricted in the gRPC layer. Enumerate every UI action, find its corresponding RPC method, and test the RPC method with lower-privilege credentials.

### Deadline Manipulation for Partial Processing
Set very short gRPC deadlines to cause timeouts in downstream services after auth has been checked but before business logic completes. If the service creates side effects (logs, audit entries, partial state changes) before the deadline expires, the partial processing may be exploitable.

## Pro Tips

1. grpcurl is the essential tool; also use grpcui for an interactive web interface
2. Always test with and without TLS; some services listen on both plaintext and TLS ports
3. Reflection is the most common misconfiguration; finding it enabled in production is a significant finding
4. gRPC-Gateway endpoints expose the same vulnerabilities as the underlying gRPC methods but through REST
5. Protobuf field numbers, not names, identify fields; renamed fields are still compatible
6. Check for protobuf JSON transcoding: some servers accept JSON content-type
7. Streaming methods are often under-tested for authorization; per-message auth is rare
8. Internal gRPC services exposed through load balancers or Kubernetes ingress are common findings
9. Reflection in URL path segments is under-tested; `/category/<segment>/method` where the segment is user input deserves the same injection testing as query parameters
10. For any RPC service behind a CDN or cache: enumerate every header and metadata key that is reflected in cached responses and test for cache poisoning

## Summary

gRPC security depends on disabling reflection in production, enforcing authentication via interceptors on every method, validating object ownership in message fields, and securing metadata propagation across service boundaries.
