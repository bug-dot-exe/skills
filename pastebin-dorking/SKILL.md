---
name: pastebin-dorking
category: reconnaissance
description: Search paste sites (Pastebin, Ghostbin, rentry, dpaste, JustPasteIt, etc.) for leaked credentials, API keys, internal URLs, and source-code snippets referring to the target
depends_on: []
---

# Pastebin Dorking

Paste sites are the forgotten dumping ground of the internet. Developers use them to share code snippets with colleagues, attackers use them to dump breached credentials, and both groups frequently forget to delete. A target organization's name appearing on Pastebin almost always signals leaked configuration, credentials, or source code.

## When to Use

- Any target with >50 employees (someone has pasted something)
- After github_dorking finds nothing — paste sites are often an alternative channel
- After a breach is rumored (paste sites are the first place dumps appear)
- Hunting for credentials that can be credential-stuffed against login forms
- Looking for internal URLs, admin endpoints, or API keys that didn't hit git

## Methodology

### Phase 1: Direct Paste Search

1. Search each paste site for the target's domain + `@target.com` (email leaks)
2. Search for the target's org name + common credential words (password, api_key, token)
3. Search for the target's infrastructure keywords (jenkins url, okta subdomain, VPN endpoint)
4. Archive anything you find immediately — pastes get deleted

### Phase 2: Aggregator Search

1. Query **IntelligenceX** (`intelx.io`) — indexes most paste sites + darknet pastes
2. Query **Psbdmp** (`psbdmp.ws`) — Pastebin-specific full-text search, bypasses Pastebin's own weak search
3. Query **DumpSterDiver** / **Dehashed** — focuses on leaked credentials
4. Use **Google** as an aggregator: `site:pastebin.com "target.com"`, `site:rentry.co "target.com"`

### Phase 3: Historical and Deleted Pastes

1. Check **Wayback Machine** for deleted paste URLs (archive.org caches many pastes)
2. **CachedView** (`cachedview.com`) — snapshots from Google/Bing/Yandex caches
3. Pastebin's own API (`scraping.pastebin.com/api_scraping.php`) requires paid membership but returns 100 most-recent pastes in real time — useful for monitoring

### Phase 4: Real-Time Monitoring

If the program scope permits long-running recon:

1. Subscribe to paste site scraping APIs (Pastebin Scraping API, ChronoBin)
2. Run **PasteHunter** or **Dumpster-Diver** locally to grep incoming pastes for your target keywords
3. Set up Twitter/Mastodon keyword alerts for `target.com pastebin`

## Paste Sites to Query

| Site | Search URL | Notes |
|------|-----------|-------|
| Pastebin.com | `pastebin.com/search?q=<term>` | Weak on-site search; prefer Google `site:` |
| Ghostbin | `ghostbin.com` | Often used by security researchers; requires Google dorking |
| rentry.co | `rentry.co` | Newer, popular for markdown pastes; `site:rentry.co "target.com"` |
| dpaste.org | `dpaste.org` | Django community; `site:dpaste.org "target.com"` |
| dpaste.com | `dpaste.com` | Different service, same idea |
| paste.ee | `paste.ee` | European paste site |
| JustPasteIt | `justpaste.it` | Long-form paste; often used for full configs |
| ControlC | `controlc.com` | Old but still indexed |
| hastebin / hastebin.com | `hastebin.com` | Used by Discord bot users / gamers |
| gist.github.com | `gist.github.com` | Covered in github_dorking.md |
| paste.debian.net | `paste.debian.net` | Linux community leaks |
| paste.org.ru | `paste.org.ru` | Russian-language paste site |
| termbin.com | `termbin.com` | Pastes from `nc termbin.com 9999` shell users |

## Key Queries

```
# Google site: dorks for paste sites
site:pastebin.com "target.com"
site:pastebin.com "target.com" "password" OR "secret" OR "api_key"
site:rentry.co "target.com"
site:ghostbin.com "target.com"
site:dpaste.org "target.com"
site:justpaste.it "target.com"
site:paste.ee "@target.com"                 # employee emails

# Aggregator searches (Google finds pastes Pastebin itself can't)
site:pastebin.com intext:"target.com" intext:"BEGIN RSA PRIVATE KEY"
site:pastebin.com intext:"target.com" intext:"AKIA"          # AWS
site:pastebin.com intext:"target.com" intext:"ghp_"          # GitHub tokens
site:pastebin.com intext:"target.com" filetype:txt

# Paste-specific search engines
# https://psbdmp.ws/api/search/target.com        (Psbdmp)
# https://intelx.io/?s=target.com                (IntelligenceX web)

# IntelligenceX API
curl "https://2.intelx.io/phonebook/search?selector=target.com&k=<API_KEY>"
```

## Corpus-Derived Hunting Patterns

### Client-Supplied Field Mask Override

When a server-side response is shaped by a client-supplied `fields=`/projection/mask parameter, treat each non-masked field as a potential data leak. Technique:
1. Capture a normal API response and note which fields are returned
2. Search paste sites for API documentation or Swagger snippets showing the full schema
3. Add undocumented fields to the `fields=` parameter or remove the mask entirely
4. If the server returns fields the UI never displays, those fields often contain sensitive data (internal IDs, PII, tokens)

### Cross-Product Identifier Leakage

When a product family integrates many tools, identifiers from one product (object IDs, session tokens, API keys) often leak into another product's response or paste. Search for:
- Integration/helper feature URLs containing cross-product IDs
- Webhook payloads pasted for debugging that contain auth tokens
- Error logs pasted with full request/response bodies including authorization headers

### SDK Serialization Credential Leaks

Any SDK that handles credentials may serialize them into user-visible output. Search pastes for:
1. `JSON.stringify(obj)` output containing SDK objects with embedded keys
2. `console.log` output of database/API client objects
3. Stack traces that include credential objects in the call stack
4. Error messages that stringify the configuration object (including secrets)

### Pre-Auth Preview Surface Exploitation

For any platform with email-based invitations (collaboration, team membership, file shares):
1. Search pastes for invitation URLs with embedded tokens
2. Test whether the preview page (before login) reveals metadata (titles, participant names, content snippets)
3. These previews often leak more data than intended because they are designed for the invitee, not for anonymous visitors

### Privacy Boundary Leakage via Secondary Metadata

When a system supports "act as other identity" (Page-as-actor, Org-as-actor, Service-account-as-actor):
1. Search pastes for API responses showing the acting identity's metadata
2. Check whether the actor identity leaks through: activity logs, notification payloads, "created_by" fields, analytics tags
3. These secondary metadata channels often bypass the privacy controls applied to the primary data

### Marketplace Integration JWT Leaks

Whenever a third-party marketplace app (Atlassian, Salesforce, Slack, Microsoft 365) exposes configuration pages:
1. Search pastes for the app's callback URLs or webhook endpoints
2. Look for JWTs or shared secrets pasted during integration setup
3. Test whether the integration's role check delegates to the marketplace or validates locally -- gaps here let unauthorized users access privileged integration features

## What to Look For

**Immediate Wins**
- Email/password pairs from prior breaches (credential stuffing candidates)
- Live API keys pasted for "debugging" (often never rotated)
- VPN config files (`.ovpn`) with embedded credentials
- SSH private keys pasted to share with a colleague
- Database dumps with column structure + sample rows

**Infrastructure Intel**
- Internal wiki/Confluence URLs (`https://target.atlassian.net/...`)
- Jenkins/Jira/GitLab self-hosted URLs
- Okta / OneLogin SSO subdomain (`target.okta.com`)
- Slack webhook URLs (for RCE via webhook flooding or internal message injection)

**Code Intelligence**
- Error dumps with file paths (`/var/www/target-api/src/...`)
- Dependency lock files revealing versions + vulns
- Log snippets showing internal API routes, parameter names
- Development notes / TODO comments (sometimes with credentials)

## Validation

1. Never use discovered credentials against production — validate against login-check endpoints only
2. Check if the paste is authentic (random people sometimes paste hoaxes referencing well-known brands)
3. Cross-reference against HaveIBeenPwned to confirm breach attribution
4. Timestamp matters: pastes from >2 years ago may have been rotated
5. Report to the program with the paste URL, date, and exact leaked content — never re-paste the credentials

## Tips

1. Search the target's domain, subsidiaries' domains, and any known acquisitions
2. Search employee email formats (`firstname.lastname@target.com` and variants)
3. Search internal product codenames found in github_dorking.md — these are often in pastes
4. Search the target's developer forums / Discord server names on paste sites
5. When a paste has been deleted, try its ID on `archive.org/wayback/available?url=pastebin.com/<id>`
6. Run regex across scraped pastes locally with `gf` patterns (linkedin `.js` leaks, `.env` blobs) for automation
7. Pastebin's "scraping API" is paid but worth it for active programs — real-time feed of all public pastes
8. DELETE endpoints often have the weakest authorization checks -- if you find an API endpoint in a paste, test destructive operations first
