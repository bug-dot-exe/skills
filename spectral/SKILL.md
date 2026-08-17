---
name: spectral
description: Spectral OpenAPI/AsyncAPI/Arazzo linter — security validation against OWASP API Top 10, HTTPS enforcement, auth-defined checks, and custom organizational rules
depends_on: []
---

# Spectral API Specification Linter

Spectral validates OpenAPI v2/v3, AsyncAPI v2, and Arazzo v1 specifications against built-in and custom rulesets. For application security, the highest-value use is enforcing OWASP API Security Top 10 mechanically at the spec layer — before the API ships.

## Prerequisites

- Node.js 16+ and npm (install: `apt install nodejs npm` or use a Node version manager)
- Spectral CLI (install: `npm install -g @stoplight/spectral-cli`, or run via Docker: `docker run -v $(pwd):/tmp stoplight/spectral lint /tmp/openapi.yaml`)

## Canonical Syntax

`spectral lint <spec> [flags]` — `<spec>` is a path to an OpenAPI/AsyncAPI YAML or JSON file (or a glob).

## High-Signal Flags

- `--ruleset <path>` use a custom ruleset file (`.spectral.yaml` / `.spectral.json` / `.spectral.js`)
- `-f, --format stylish|json|junit|html|github-actions|teamcity|sarif` output format
- `-o, --output <file>` write report to file
- `--fail-severity error|warn|info|hint` non-zero exit when finding at least this severity
- `--fail-on-unmatched-globs` exit non-zero if no specs matched the glob
- `-v, --verbose` show match details and rule provenance
- `-D, --display-only-failures` hide passing rules
- `--encoding utf8|ascii` source encoding (default utf8)
- `--ignore-unknown-format` skip files Spectral can't parse

## Built-in Rulesets

Extend these in your `.spectral.yaml` to inherit baseline checks:

- `spectral:oas` — OpenAPI v2/v3 best practices (most security-relevant)
- `spectral:asyncapi` — AsyncAPI v2 validation
- `spectral:arazzo` — Arazzo v1 workflow specifications

## Agent-Safe Baseline

```bash
spectral lint openapi.yaml \
  --ruleset .spectral.yaml \
  --format json \
  --output spectral.json \
  --fail-severity error
```

Returns exit-code 1 if any `error`-severity finding exists, JSON report saved for downstream parsing.

## Common Patterns

- **Quick OAS-only scan**:
  `spectral lint openapi.yaml --ruleset spectral:oas --format stylish`
- **CI-friendly GitHub Actions output**:
  `spectral lint openapi.yaml --format github-actions`
- **Multiple specs at once**:
  `spectral lint 'specs/*.yaml' --ruleset .spectral.yaml --output spectral.json --format json`
- **Errors-only (mute warnings/info)**:
  `spectral lint openapi.yaml --display-only-failures --fail-severity error`

## OWASP API Top 10 Ruleset Skeleton

Save as `.spectral-owasp.yaml`:

```yaml
extends: [[spectral:oas, all]]

rules:
  # API1: Broken Object Level Authorization
  operation-security-defined:
    severity: error
    message: "Every operation must declare security (OWASP API1)"

  # API2: Broken Authentication
  security-schemes-defined:
    severity: error
    message: "API must define security schemes (OWASP API2)"

  # API3: Broken Object Property Level Authorization
  no-additional-properties:
    severity: warn
    message: "Consider disabling additionalProperties to prevent data leakage (OWASP API3)"

  # API7 & API8: HTTPS-only servers
  servers-use-https:
    description: All server URLs must use HTTPS
    severity: error
    given: $.servers[*].url
    then:
      function: pattern
      functionOptions:
        match: "^https://"
    message: "Server URL must use HTTPS (OWASP API7/API8)"

  # API8: No HTTP Basic Auth
  no-http-basic:
    description: HTTP Basic auth transmits credentials in plain text
    severity: error
    given: $.components.securitySchemes[*]
    then:
      field: scheme
      function: pattern
      functionOptions:
        notMatch: "^basic$"
    message: "Avoid HTTP Basic auth (OWASP API8)"

  # API9: Improper Inventory Management
  api-version-required:
    severity: error
    given: $.info
    then:
      field: version
      function: truthy
    message: "API version must be specified (OWASP API9)"

  # Defense-in-depth: PII never in query strings
  no-pii-in-query:
    description: Prevent PII exposure in URL query parameters
    severity: error
    given: $.paths[*][*].parameters[?(@.in == 'query')].name
    then:
      function: pattern
      functionOptions:
        notMatch: "(?i)(ssn|social.?security|credit.?card|password|secret|token)"
    message: "Query parameters must not contain PII or secrets"
```

Run: `spectral lint openapi.yaml --ruleset .spectral-owasp.yaml`

## Custom Rule Authoring

Each custom rule has four fields:
- `description` — human-readable purpose
- `severity` — `error` / `warn` / `info` / `hint`
- `given` — JSONPath expression selecting the spec nodes to check
- `then` — function (`truthy`, `falsy`, `pattern`, `enumeration`, `length`, `schema`, `xor`, `alphabetical`, `unreferencedReusableObject`) plus options
- `message` — finding text

For complex predicates (e.g., contextual checks across nodes), Spectral supports JS/TS custom functions referenced via `functions:` in the ruleset.

## Critical Correctness Rules

- Spectral's exit code reflects findings only when `--fail-severity` is set; without it, exit 0 even on critical findings.
- A `given` JSONPath that matches nothing produces NO findings (silent pass) — use `--fail-on-unmatched-globs` and `-v` to verify rule coverage.
- Multi-document YAML is not supported; split into separate files or convert to single-doc JSON.
- Severity in extends propagates: if `spectral:oas` declares a rule as `warn`, override with `<rule>: error` in your overlay.

## Failure Recovery

- If lint output is empty, verify the spec parses with `--verbose` — Spectral skips files it can't classify.
- If a custom rule "doesn't fire" on an obvious violation, test the JSONPath separately with `jp` or `jq -p` against the parsed YAML.
- For very large specs, use `-D` to skip passing rules and reduce log noise.

## SecOpsAgentKit contributions

Sourced from SecOpsAgentKit's `appsec/api-spectral/SKILL.md` (OWASP API Top 10 ruleset skeleton, custom rule authoring patterns, output format selection guidance). Adapted to bug.exe's CLI-playbook format.

## Corpus-Derived Advanced Workflows (294 reports, $3.7M bounty)

### GraphQL Schema Authorization Audit ($50K+ pattern)

When a GraphQL API exposes its schema, lint for sensitive field patterns:

```bash
# Extract schema and lint for sensitive fields
curl -s https://api.target.tld/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' > schema.json

cat > .spectral-graphql.yaml << 'EOF'
extends: [[spectral:oas, off]]
rules:
  sensitive-field-exposure:
    severity: error
    given: "$..fields[*].name"
    then:
      function: pattern
      functionOptions:
        notMatch: "(?i)(private_|internal_|admin_|secret_|password|token|key|ssn|credit)"
    message: "Field name suggests sensitive data — verify resolver-level auth"
EOF
spectral lint schema.json --ruleset .spectral-graphql.yaml --format json -o graphql_audit.json
```

### Validate-and-Use Mismatch Detection ($62.5K pattern)

When a URL/string flows through a system, find where validation parses it differently than consumption. Custom rule to detect URL parameters without format validation and redirect parameters without allowlisted destinations:

```yaml
# .spectral-url-mismatch.yaml
extends: [[spectral:oas, all]]
rules:
  url-parameter-no-format:
    severity: warn
    given: "$.paths[*][*].parameters[?(@.schema.type == 'string')]"
    then:
      - field: schema.format
        function: truthy
    message: "String parameter may accept URLs — add format:uri or pattern validation"
  redirect-no-enum:
    severity: error
    given: "$.paths[*][*].parameters[?(@.name =~ /redirect|return|next|url|callback/i)]"
    then:
      - field: schema.enum
        function: truthy
    message: "Redirect parameter should restrict allowed values via enum"
```

### Cross-Product Field Leakage Detection ($20K pattern)

When APIs return verbose error messages, they may leak parameter names and internal structure. Enforce error response schemas and restrict `additionalProperties`:

```yaml
# .spectral-error-leak.yaml
extends: [[spectral:oas, all]]
rules:
  error-response-schema:
    severity: warn
    given: "$.paths[*][*].responses[?(@property >= '400' && @property < '600')]"
    then:
      field: content.application/json.schema
      function: truthy
    message: "Error response lacks schema — may leak internal structure in production"
  no-additional-props-on-response:
    severity: warn
    given: "$.paths[*][*].responses[*].content.application/json.schema"
    then:
      field: additionalProperties
      function: falsy
    message: "Response allows additionalProperties — may leak fields to lower-privilege callers"
```

### Defense-in-Depth Rules (Unicode, Cache)

Flag unbounded string parameters (normalization bypass, $1.7K) and missing cache-control (poisoning, $4.5K):

```yaml
# .spectral-defense.yaml — add to your OWASP ruleset
extends: [[spectral:oas, all]]
rules:
  string-no-pattern:
    severity: info
    given: "$.paths[*][*].parameters[?(@.schema.type == 'string' && !@.schema.pattern && !@.schema.enum)]"
    then: { field: schema.maxLength, function: truthy }
    message: "Unbounded string — add pattern/maxLength to prevent normalization bypasses"
  cache-control-on-sensitive:
    severity: error
    given: "$.paths[*][*].responses['200']"
    then: { field: headers.Cache-Control, function: truthy }
    message: "Missing Cache-Control — cache poisoning risk on CDN-fronted deployments"
```

### Chaining Spectral with Other Tools

1. **subfinder -> httpx -> spectral**: discover hosts, probe for OpenAPI endpoints, lint the specs
2. **spectral -> nuclei**: spec-level findings identify which endpoints need active testing
3. **mitmproxy -> spectral**: captured traffic converted to HAR then OpenAPI for retroactive linting
4. **spectral -> semgrep**: spec findings guide semgrep custom rules for source-code authorization checks
