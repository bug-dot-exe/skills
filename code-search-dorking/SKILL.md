---
name: code-search-dorking
category: reconnaissance
description: Search engines that index raw source code beyond GitHub — grep.app, Sourcegraph, PublicWWW, searchcode, NerdyData — for exposed snippets, hardcoded secrets, and target-specific integrations
depends_on: []
---

# Code Search Dorking

github_dorking covers GitHub only. A huge amount of leakable code lives elsewhere: GitLab, Bitbucket, self-hosted forges, NPM tarballs, built/minified frontend bundles, Docker image layers, CI job logs. Specialized code search engines index this broader universe.

Use this skill as a complement to — not a replacement for — `github_dorking.md`.

## When to Use

- github_dorking came up empty but the target clearly has engineering staff
- Looking for secrets in minified JavaScript bundles (production source)
- Hunting for references to the target in third-party code (integration leaks)
- Finding custom-built auth flows copied into multiple projects
- Need to search millions of web pages' raw HTML/JS for a specific fingerprint

## Methodology

### Phase 1: Pick the Right Engine per Use Case

| Use Case | Best Engine | Why |
|----------|-------------|-----|
| Raw code across GitHub + GitLab + Bitbucket + more | **Sourcegraph** (`sourcegraph.com/search`) | Indexes millions of repos across multiple forges |
| Regex search across GitHub only, extremely fast | **grep.app** (`grep.app`) | Fastest GitHub code search available |
| Target fingerprint in deployed HTML/JS (live web) | **PublicWWW** (`publicwww.com`) | Indexes the HTML + JS of millions of live sites |
| Historical / academic code repos | **searchcode.com** | Indexes SourceForge, Bitbucket, Google Code, code.launchpad.net |
| "Which sites use this library version?" | **BuiltWith** (`builtwith.com`) + **Wappalyzer** | Live technology fingerprinting |
| Favicon / HTML asset matching | **PublicWWW**, **Shodan favicon hash**, **FavFreak** | Finds target's own assets hosted on forgotten IPs |
| Commit message / diff search | **Sourcegraph** (`type:diff`) | Other engines don't expose diffs |

### Phase 2: Run Layered Queries

Start broad, narrow progressively:

1. **Target domain across all engines**: `"target.com"`
2. **Target email domain**: `"@target.com"` (almost always appears in tests / README / comments)
3. **Target-specific keywords** from github_dorking results: internal product names, project codenames
4. **Credential patterns near target references**: `"target.com" AND (apikey OR password)`
5. **Framework signatures + target**: e.g., `"target.com" authentication middleware`

### Phase 3: Deep Dive on Hits

For any promising result:

1. Open the source file, check the full commit/file context
2. Look at the author's other repos / projects — often more leaks there
3. Check if the target has forked or starred the repo (indicates internal use)
4. Pivot to the project's CI logs, issues, and wiki

## Key Queries

### Sourcegraph (`sourcegraph.com/search`)

Sourcegraph supports regex, structural search, diffs, and filters across hundreds of code hosts.

```
# Secrets referencing the target
"target.com" AKIA[0-9A-Z]{16}
"target.com" file:\.env$
"target.com" (api_key|apikey|api-key) =

# Commits / diffs mentioning the target (not just current code)
"target.com" type:diff
repo:"target/" type:diff message:"password"

# Structural search (only on Sourcegraph)
repo:contains.path(\.env) content:"target.com"
repo:has.file(.env.production)

# Author search — employees committing from personal accounts
author:"@target.com" password

# Org-scoped
repo:github\.com/target-org file:\.yml content:"kubernetes"
```

### grep.app (GitHub only, regex-native)

grep.app is fast and supports real regex — perfect for exhaustive pattern sweeps.

```
# Regex patterns — literal @, escape . in UI
target\.com.*AKIA[0-9A-Z]{16}
target\.com.*sk_live_
target\.com.*mongodb(\+srv)?://
target\.com.*(bearer|authorization)\s*[:=]

# Literal search (UI toggle "regex" off)
target.com BEGIN RSA PRIVATE KEY
target.com .env.production
target.com firebaseio.com

# Filter by language
lang:javascript target.com api_key
lang:yaml target.com secret
lang:dockerfile target.com
```

### PublicWWW (live HTML/JS source, not git)

PublicWWW is different — it indexes what is *currently deployed* on live websites.

```
# Find all sites that embed the target's widget / tracker / SDK
"<script src='https://cdn.target.com/sdk.js'>"
"cdn.target.com" .js

# Find sites with the target's Stripe/analytics key (broken into classpath)
"analytics-key-123"
"pk_live_ABC"                    # if you already have a fingerprint

# Favicon hash match (find target's dev/staging instances)
"favicon.ico" md5:d41d8cd98f00b204e9800998ecf8427e

# Third-party integrations on target pages
"site:target.com" "pingdom" OR "bugsnag" OR "mixpanel"
```

### searchcode.com (SourceForge + legacy repos)

Old but sometimes uniquely valuable for discovering abandoned projects referencing the target.

```
"target.com" filename:config
"target.com" password
"target.com" ext:sql
```

### NerdyData (`search.nerdydata.com`)

Commercial but has a free tier. Indexes ~500M websites' HTML/JS source.

```
# Find sites using target's JS library
"https://cdn.target.com"

# Find sites with matching analytics IDs (pivot to related properties)
"UA-12345678-1"

# Find abandoned apps using target's API keys
"api.target.com/v1"
```

### Other engines worth a look

- **Searx / SearXNG** (`searx.be`) — meta-engine that hits multiple code search backends simultaneously
- **ChatGPT/Perplexity** — sometimes regurgitates cached code from training data (use with skepticism)
- **Google Code Search clone** via `site:pastebin.com | site:gitlab.com | site:bitbucket.org` (Google itself is still an excellent code search)

## What to Look For

**Beyond GitHub**
- GitLab self-hosted instances (`gitlab.target.com` or `code.target.com`)
- Bitbucket repositories (still used heavily by enterprise teams)
- Gitea / Gogs self-hosted (often forgotten)
- NPM-published private modules accidentally marked public
- Source maps (`.js.map`) deployed to production — full original source

**Target-Specific Patterns**
- Internal API base URLs (`api-internal.target.com`, `prod-api.target.com`)
- Custom header names (`X-Target-Auth`, `X-TargetCorp-Trace-ID`)
- Rate-limit bypass secrets (`target-internal-bypass-key`)
- Feature-flag provider keys (LaunchDarkly, Split.io, Optimizely SDK keys)

**Third-Party Leaks**
- Integration code shared by partners / customers / ex-employees
- Sample code in SDK documentation that accidentally includes prod credentials
- Code review comments on open-source PRs from target employees

## Validation

1. Confirm the target actually uses the code (many hits are coincidental domain-name collisions)
2. Cross-reference with github_dorking to see if the same author has GitHub activity
3. For PublicWWW / BuiltWith hits, visit the site to confirm the fingerprint is current
4. Verify API keys are live before reporting (non-destructive endpoints only)

## Corpus-Derived Hunting Patterns

Techniques from disclosed reports where code search was the critical discovery vector.

### Shared Component Vulnerability Mapping

When a CVE is published for an OSS component (Code OSS, Lodash, Express, Mermaid, Markdown-it):

1. Search all code hosts for the component's package name or import statement
2. For each target that bundles the vulnerable version, check if the vulnerability is reachable in their integration context
3. Upstream fixes propagate slowly — targets often run 6-12 months behind on vendored dependencies

```
# Sourcegraph: find targets bundling a vulnerable version
"lodash": "4.17.20" file:package.json
"mermaid": "9." file:package.json

# grep.app: regex for known-vulnerable version ranges
express.*4\.17\.[0-9]  lang:json
```

### Sink-Driven XSS Discovery

Search for dangerous rendering APIs in the target's frontend code:

```
# grep.app: framework-specific XSS sinks
v-html  repo:target-org lang:vue
dangerouslySetInnerHTML  repo:target-org lang:jsx
bypassSecurityTrustHtml  repo:target-org lang:typescript
html_safe  repo:target-org lang:ruby
messageHtml:  repo:target-org lang:javascript
```

For each hit, trace back to find which user input reaches the sink. Sinks in admin panels, email templates, and notification renderers are high-value because they are less audited.

### Unsafe Deserialization Pattern Sweep

For every target codebase, search for deserialization calls on any data crossing a trust boundary:

```
# Ruby
YAML.load  repo:target-org lang:ruby
Marshal.load  repo:target-org lang:ruby

# Python
pickle.load  repo:target-org lang:python
yaml.load  repo:target-org lang:python

# Java
ObjectInputStream  repo:target-org lang:java
readObject  repo:target-org lang:java

# PHP
unserialize  repo:target-org lang:php
```

### Integration Artifact Hunting

Third-party integration code often leaks credentials:

1. Search for files that declare integration configurations: `Gemfile`, `package.json`, `requirements.txt`, `docker-compose.yml`, `.env.example`
2. Look for internal package names (`@target-corp/`, `@internal/`) — dependency confusion targets
3. Check SDK documentation samples from the target's developer portal — sample code sometimes includes production credentials

```
# Sourcegraph: find internal package references across public repos
"@target-corp/" file:package.json
repo:contains.path(Gemfile) content:"target-internal"
```

### Android/iOS Exported Component Audit

For mobile app targets, decompile and search for attack surface:

```
# grep.app: exported Android activities (deeplink/intent attack surface)
android:exported="true"  repo:target-org lang:xml
addJavascriptInterface  repo:target-org lang:java
```

## Tips

1. Sourcegraph + grep.app are complementary — run both
2. PublicWWW is the only engine that finds leaks in *production* frontend bundles (massive win)
3. `.js.map` files are the #1 source of full server-side source code leaks — always grep for them
4. For enterprise targets, check GitLab self-hosted on `code.`, `git.`, `gitlab.`, `src.`, `source.` subdomains
5. Some targets have bounty programs that specifically forbid certain code search engines (check scope)
6. Sourcegraph has a free-tier API — automate queries with `curl https://sourcegraph.com/.api/graphql`
7. Export findings to JSON immediately — search indexes turn over quickly
