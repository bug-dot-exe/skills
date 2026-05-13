---
name: spring-boot
description: Spring Boot attack surface: Actuator exposure, SpEL injection, deserialization, OAuth2 misconfig
depends_on: []
---

# Spring Boot

Spring Boot is the dominant Java framework. Actuator endpoints (`/actuator/*`) commonly leak heap dumps, env vars, mappings. Spring4Shell (CVE-2022-22965) and SpEL injection (`#{}`) are recurring patterns.

## Common Bug Classes

- Actuator endpoints exposed: `/actuator/heapdump`, `/actuator/env`, `/actuator/mappings`
- SpEL injection in routes using `@PreAuthorize("#user == ...")` with user input
- Java deserialization on RMI / management ports
- Spring Cloud Gateway SSRF via reachable filters
- OAuth2 misconfig: `redirect_uri` validation regex too permissive
- Whitelabel error page disclosing class hierarchy

## Actuator Endpoint Exploitation

Actuator is the highest-yield Spring Boot attack surface. Maintain a comprehensive probe list:

```
# Information disclosure
/actuator/env           # Environment variables, secrets, API keys
/actuator/configprops   # All configuration properties
/actuator/mappings      # All URL mappings (reveals hidden endpoints)
/actuator/beans         # All Spring beans (architecture disclosure)
/actuator/info          # Application info, git commit, build version
/actuator/conditions    # Auto-configuration conditions

# Data exfiltration
/actuator/heapdump      # Full JVM heap → extract secrets, sessions, credentials
/actuator/threaddump    # Thread state → timing/race condition intelligence

# Management operations
/actuator/shutdown      # POST to gracefully shut down (if enabled)
/actuator/restart       # Restart the application
/actuator/refresh       # Refresh configuration
/actuator/loggers       # Change log levels at runtime (enable DEBUG)
/actuator/jolokia       # JMX over HTTP → arbitrary MBean operations → RCE

# Health and metrics
/actuator/health        # Health status (may include database, cache details)
/actuator/metrics       # Application metrics
/actuator/prometheus    # Prometheus metrics export
```

**Escalation from info to RCE:**
1. `/actuator/env` reveals database credentials → direct database access
2. `/actuator/heapdump` → extract active session tokens, API keys from heap
3. `/actuator/jolokia` → invoke arbitrary MBeans → code execution
4. `/actuator/gateway/routes` (Spring Cloud Gateway) → SSRF via route creation

## Adjacent Service Enumeration

Once you find ONE exposed component (e.g., Eureka at port 8761), the rest of the stack shares misconfiguration:

1. Find Eureka → enumerate all registered services and their IPs/ports
2. Probe adjacent ports: Zuul Gateway (8080), Config Server (8888), Admin Server (9090)
3. Each exposed service has its own actuator endpoints
4. Kubernetes: if one service has actuator exposed, check all services in the namespace

## SpEL Injection & SSTI

Spring Expression Language injection paths:

1. **Error pages:** Spring Boot Whitelabel error page with SpEL in error attributes
2. **`@PreAuthorize` / `@PostAuthorize`:** SpEL expressions referencing request parameters
3. **Spring Cloud Function:** `spring.cloud.function.routing-expression` header injection
4. **View resolvers:** Thymeleaf, FreeMarker, Velocity template injection

**WAF bypass for SpEL:**
```
# Standard SpEL
${T(java.lang.Runtime).getRuntime().exec('id')}

# Bypass via reflection
#{T(String).class.forName('java.la'+'ng.Ru'+'ntime')}

# Bypass via new class loading
#{T(org.springframework.cglib.core.ReflectUtils)}
```

## Log4Shell & Critical CVE Response

Spring Boot applications almost always include Log4j. When critical CVEs drop:

1. **Injection surface enumeration:** Test JNDI payloads in ALL input fields, not just obvious ones:
   - HTTP headers: `User-Agent`, `X-Forwarded-For`, `Referer`, `Accept-Language`
   - Path parameters, query parameters, POST body fields
   - Cookie values, custom headers
2. **Out-of-band verification:** Use OAST tools to confirm server-side lookup
3. **Version detection:** `/actuator/info` or `/actuator/env` may reveal Log4j version directly

## Framework Version Reconnaissance

Spring Boot version detection for CVE matching:

```
# Direct version endpoints
/actuator/info          # build.version, git.commit
/version                # Custom version endpoint
/actuator/health        # Spring Boot format reveals version range

# Indirect fingerprinting
/error                  # Whitelabel error page format varies by version
/actuator               # Response format changed between Boot 1.x and 2.x
# Boot 1.x: /health, /env, /metrics (no /actuator/ prefix)
# Boot 2.x: /actuator/health, /actuator/env
```

## Management Interface Enumeration

Beyond Actuator, Spring Boot apps often expose management interfaces:

- **Jolokia:** `/actuator/jolokia/list` → enumerate MBeans → invoke operations
- **JMX ports:** Default 1099, 9090 — often unauth on internal networks
- **Spring Boot Admin:** Web UI for managing Boot applications → if exposed, full control
- **Hazelcast:** Management center if embedded, with cluster operations

For each exposed management interface: enumerate all available operations and test each for arbitrary code execution potential.

## Host Header Poisoning

Spring Boot on PaaS platforms (Heroku, AWS Elastic Beanstalk, Azure App Service):

1. Test `Host` header injection for cache poisoning and password reset link manipulation
2. Test `X-Forwarded-Host` when behind reverse proxy (Nginx, Apache, AWS ALB)
3. Spring Boot's `server.use-forward-headers=true` trusts `X-Forwarded-*` headers

## Probe Targets

- Probe `/actuator/`, `/actuator/health`, `/actuator/env`, `/actuator/heapdump` (binary), `/actuator/mappings`
- Test `?class.module.classLoader.URLs[0]=` (Spring4Shell signature)
- Hit `/error` with malformed inputs to trigger Whitelabel
- Look for `/oauth/`, `/oauth2/`, `/login/oauth2/code/*`
- Test `/actuator/jolokia/list` for JMX exposure
- Probe `/actuator/gateway/routes` for Spring Cloud Gateway SSRF
- Check Boot 1.x paths without `/actuator/` prefix: `/env`, `/health`, `/mappings`
- Test `spring.cloud.function.routing-expression` header for SpEL injection

## Cross-References

`api_security`, `ssrf`, `insecure_deserialization`, `oauth`, `information_disclosure`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
- For Actuator exposure: demonstrate sensitive data extraction (secrets, heap content), not just endpoint availability
- For SpEL: demonstrate code execution or data exfiltration, not just expression evaluation
