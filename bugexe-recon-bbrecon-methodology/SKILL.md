---
name: bbrecon_methodology
category: reconnaissance
description: Bug bounty recon methodology covering scope interpretation, reconnaissance phases, and attack surface discovery in modern architectures
depends_on: []
---

# Bug Bounty Recon Methodology

Structured reconnaissance for bug bounty programs. From scope interpretation through passive, active, and targeted recon phases to actionable attack surface in modern SPA/API architectures.

## When to Use

- Starting reconnaissance on any bug bounty program
- Need a systematic approach instead of ad hoc tool running
- Target uses modern architecture (SPA, microservices, serverless, API-first)
- Want to maximize coverage before vulnerability hunting begins

## Methodology

### Phase 0: Scope Interpretation

Before any tool runs, read the scope carefully:

1. **Asset types**: web apps, APIs, mobile apps, source code, infrastructure
2. **Wildcard domains**: `*.target.com` means enumerate everything
3. **Exclusions**: specific subdomains, third-party services, paths
4. **Testing restrictions**: no automated scanning, rate limits, staging preference
5. **Vuln exclusions**: classes they will not accept (check before hunting)

Create a scope checklist. Every asset you test gets checked against it.

### Phase 1: Passive Reconnaissance

No packets to target. Intelligence from public sources only.

**Subdomain discovery**:
- Certificate transparency (crt.sh, Censys)
- DNS datasets (SecurityTrails, VirusTotal, PassiveTotal)
- Search engines (Google `site:`, Bing)
- Code repositories (GitHub, GitLab org search)
- Archived data (Wayback Machine, Common Crawl)

**Technology profiling**:
- Wappalyzer/BuiltWith for stack identification
- HTTP response headers for server, framework, CDN
- Job postings mentioning tech stack
- GitHub repos revealing internal tooling

**Organization mapping**:
- Acquisitions, subsidiaries, related brands
- Employee LinkedIn for internal tool names
- WHOIS cross-reference for related domains

### Phase 2: Active Reconnaissance

Direct interaction with target infrastructure.

**DNS resolution and probing**:
- Resolve all discovered subdomains
- Identify live hosts with httpx (status code, title, tech)
- Port scan key hosts (naabu on top ports)
- Banner grabbing on non-HTTP services

**Content discovery**:
- Directory brute force with technology-specific wordlists
- robots.txt, sitemap.xml, .well-known/ paths
- Common paths: /api, /admin, /debug, /health, /metrics, /swagger
- git/svn exposure checks

**Application mapping**:
- Crawl with JS rendering (katana with headless Chrome)
- Collect historical URLs (waybackurls, gau)
- Extract endpoints from JavaScript bundles
- Map API routes and parameters

### Phase 3: Targeted Reconnaissance

Focus on high-value assets identified in Phases 1-2.

**Modern SPA/API architecture**:
- Single-page apps hide routes in JavaScript bundles
- Webpack chunk analysis reveals route definitions
- API clients in JS expose every backend endpoint
- State management stores reveal data models

**API-first targets**:
- OpenAPI/Swagger documentation (if exposed)
- GraphQL introspection queries
- API versioning: test old versions alongside current
- Undocumented endpoints found via JS analysis vs documented API

**Cloud and infrastructure**:
- S3 bucket enumeration from discovered naming patterns
- Azure Blob, GCP Storage with organization-based names
- Serverless function URLs (Lambda, Cloud Functions)
- CDN origin discovery (bypass CDN to hit origin directly)

### Phase 4: Asset Prioritization

Not all discovered assets deserve equal attention:

| Priority | Asset Characteristics |
|----------|----------------------|
| Critical | Auth endpoints, payment processing, admin panels, direct (no CDN) |
| High | API endpoints with user data, file handling, integrations |
| Medium | Standard web app functionality, CDN-protected primary app |
| Low | Static content, marketing pages, documentation sites |

Factors that increase priority:
- Staging/dev environments (weaker security)
- Recently deployed features (newer = less tested)
- Endpoints with many parameters (larger attack surface)
- Services running outdated software versions

## Corpus-Derived Hunting Patterns

### Browser Extension Audit Playbook

For any browser extension installed by default or recommended by the target:
1. Pull extension source from Chrome Web Store (`.crx` file, unpack)
2. Read `manifest.json`: list `content_scripts`, `permissions`, `externally_connectable`, `web_accessible_resources`
3. For `externally_connectable`: test whether arbitrary websites can send messages to the extension
4. For content scripts with `<all_urls>`: trace every `postMessage` and `chrome.runtime.sendMessage` for UXSS vectors
5. Check if extension CSP allows external embedding via missing `frame-ancestors`

### Patch-Bypass as Primary Methodology

On mature platforms, patch-bypass hunting is one of the highest-ROI strategies:
1. When a security issue is fixed, read the patch carefully
2. Test whether the same vulnerability class still exists in adjacent code paths
3. Check if the fix can be circumvented via encoding, method swap, or parameter aliasing
4. Regional/legacy/secondary domains (China, India, Japan variants) often receive patches later

### Cloud Service Layer Auth Boundary Testing

When a cloud service is layered atop another (registry over object storage, function over container runtime):
1. Map both the outer and inner service auth boundaries
2. Test whether credentials scoped to the outer service grant unscoped access to the inner service
3. Check whether the inner service enforces the outer service's tenant isolation

### OAuth Scope Exhaustive Enumeration

For any OAuth provider with many scopes:
1. Enumerate every scope the provider supports (not just what the UI offers)
2. For each scope, test every API endpoint it grants access to
3. Check for scope inheritance: does scope A implicitly include scope B's capabilities?
4. Test whether deprecated scopes still work and have broader permissions than their replacements

### Argument Injection Survey

For any application that shells out to a CLI tool with user-controlled values:
1. Identify the CLI tool (git, ffmpeg, ImageMagick, curl, etc.)
2. Map every argument position that takes user input
3. Test flag injection: add `--` prefix, `-o outputfile`, `--config /etc/passwd`
4. Search for the tool's `--` (end of options) handling -- if the app doesn't use it, flags can be injected

### LLM-as-Access-Control-Bypass

For any platform where an LLM has privileged content access (summarization, search, Q&A over private data):
1. Test whether user queries can extract content the user cannot directly access
2. Craft prompts that ask the LLM to quote, paraphrase, or summarize restricted content
3. The LLM becomes an access-control bypass primitive when the authorization check is on the UI, not the LLM's data access layer

### Cross-Sandbox Shared State Exploitation

When auditing multi-policy/multi-language platforms:
1. Identify all sandboxes (script runners, policy engines, plugin contexts)
2. Map shared state between sandboxes (global objects, env vars, temp files, class loaders)
3. If sandbox A writes to shared state and sandbox B reads it, test whether A can manipulate B's execution context

## Recon Outputs

Structure your recon results for hunting:

```
target.com/
  subdomains.txt        # All discovered subdomains
  live_hosts.txt        # Resolved, responding hosts
  urls.txt              # All discovered URLs with parameters
  api_endpoints.txt     # API routes mapped
  tech_stack.txt        # Technology fingerprints per host
  js_endpoints.txt      # Routes extracted from JavaScript
  params.txt            # All unique parameter names
  priority_targets.txt  # Ranked assets for hunting
```

## Common Mistakes

- Running tools without reading scope first
- Scanning out-of-scope assets and getting banned
- Stopping at subdomain enumeration without content discovery
- Ignoring JavaScript analysis on modern SPAs
- Not checking historical data for deprecated but live endpoints
- Treating all assets equally instead of prioritizing

## Tooling -- structured scanner output

Bugdotexe fires an automated blackbox pipeline in the background at
scan start (subfinder + ffuf + katana + nuclei + httpx + more). When
it finishes, its raw JSON lives in the sandbox -- don't read that by
hand. Call `summarize_scanner_output(tool_name=<nuclei|ffuf|katana|
...>, format=<condensed|full>)` to get a structured, deduplicated,
severity-ranked view suitable for deciding next probes.

Also call it AFTER any ad-hoc tool you fire (nuclei template run,
ffuf wordlist pass, dirsearch scan) -- it normalizes output across
tools and surfaces only the novel findings (dedups against what's
already been observed this scan).

Skipping the summarizer and greping raw JSON wastes tokens AND
misses structured cross-tool deduplication.
