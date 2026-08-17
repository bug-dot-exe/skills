---
name: asp-net
description: ASP.NET attack surface: ViewState deserialization, IIS misconfig, .axd handler abuse
depends_on: []
---

# Asp Net

ASP.NET (Framework + Core) ships rich functionality. ViewState (HMAC-signed serialized state) — leaked machineKey enables RCE via Marshal-style deserialization. .axd handlers and Trace.axd commonly exposed.

## Common Bug Classes

- ViewState deserialization with leaked `machineKey` → RCE
- Trace.axd / WebResource.axd / ScriptResource.axd information disclosure
- IIS short-name disclosure via `~` tilde requests
- Forms authentication ticket forgery with leaked validation key
- Verbose .NET stack traces in custom error pages

## ViewState & Deserialization Deep Dive

ViewState is the highest-severity ASP.NET-specific attack surface.

**Detection:**
- Look for `__VIEWSTATE` hidden field in form HTML (sometimes renamed to `VSTATE` or custom names)
- Custom names indicate the developer rolled their own state — likely weaker validation
- Base64-decode the value; if it starts with `/w` it is typically serialized .NET objects

**Exploitation chain:**
1. Check if ViewState is MAC-protected (look for `__VIEWSTATEGENERATOR` and `__EVENTVALIDATION`)
2. If MAC is disabled or key is leaked: craft malicious serialized payload via `ysoserial.net`
3. Key sources: `web.config` exposure, Trace.axd dumps, error messages, backup files

**Non-standard parameter names:** When a target uses `VSTATE` instead of `__VIEWSTATE`, assume the developer rolled their own — check for missing MAC validation entirely.

## Debug Endpoint Discovery

ASP.NET ships multiple debug surfaces that are frequently left enabled:

```
# ASP.NET Framework specific
/Trace.axd                    # Request traces with headers, cookies, form data
/elmah.axd                    # Error logging with full stack traces
/WebResource.axd?d=...        # Embedded resources (can leak assembly info)
/ScriptResource.axd?d=...     # Script resources
/_layouts/15/start.aspx       # SharePoint default layouts

# ASP.NET Core specific
/swagger/                     # API documentation
/swagger/v1/swagger.json      # Full API schema
/health                       # Health check endpoints
/_framework/blazor.boot.json  # Blazor app manifest

# IIS specific
/web.config                   # Configuration (should be blocked but test)
/iisstart.htm                 # Default IIS page
```

**Always mine config disclosures for follow-up attack surface:**
- `.htaccess`/`web.config` reveal handlers, rewrites, proxy targets, auth zones
- Connection strings in error pages → database targeting
- Assembly names in stack traces → deserialization gadget chains

## CSP Bypass Patterns

For ASP.NET sites with Content Security Policy:

1. List every host in `script-src`
2. For each host, check if it serves: AngularJS CDN (template injection), jQuery with `.html()` sinks, JSONP endpoints
3. Test if `unsafe-eval` or `unsafe-inline` is present
4. Check for `nonce` reuse across requests (static nonces in cached pages)

## IIS Short-Name Enumeration

The `~` tilde attack reveals truncated file and directory names on IIS:

```
GET /A~1.aspx   → 200/404 difference reveals file existence
GET /W~1/       → directory enumeration

# Automated enumeration
# Test first 6 chars of filenames systematically
# Valid: 404 with custom error page
# Invalid: different 404 or 400
```

Use discovered short names to reconstruct full paths for: backup files (`web.config.bak`), source files, admin directories.

## CSV/Export Injection

ASP.NET applications with export features are common targets:

1. Find any feature exporting to CSV, Excel, PDF, or printable format
2. Inject formula payloads in user-controlled fields: `=CMD|'/C calc'!A1`, `=HYPERLINK("http://evil.com")`
3. Test stored fields that appear in exports (names, addresses, descriptions)
4. Check if Content-Disposition forces download vs inline rendering

## Cache Poisoning

For ASP.NET apps behind CDN/cache layers:

1. Enumerate unkeyed headers: `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`
2. Test if response body includes the injected host in URLs/redirects
3. Check `Vary` header for missing dimensions that should be part of cache key
4. ASP.NET-specific: `X-Original-URL` and `X-Rewrite-URL` can override the request path behind IIS ARR

## Subdomain Takeover Signals

ASP.NET deployments frequently use Azure services with dangling CNAME risk:

- `*.azurewebsites.net` — claim via Azure App Service
- `*.blob.core.windows.net` — claim via Azure Blob Storage
- `*.cloudapp.azure.com` — claim via Azure Cloud Service
- `*.trafficmanager.net` — claim via Azure Traffic Manager

Enumerate CNAMEs in scope and check if the target resource still exists.

## Probe Targets

- Probe `/Trace.axd`, `/elmah.axd`, `/WebResource.axd`
- IIS short-name probe: `/A~1.aspx`
- Decode `__VIEWSTATE` (base64) and check for unsigned/encrypted content
- Trigger errors and look for `.NET Framework Version:` disclosure
- Test `X-Original-URL: /admin` and `X-Rewrite-URL: /admin` for path override
- Check for exposed `/swagger/v1/swagger.json` on API targets
- Probe `/_vs/browserLink` for Visual Studio debug artifacts

## Cross-References

`insecure_deserialization`, `information_disclosure`, `session_security`, `cache_poisoning`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
- For ViewState RCE: confirm MAC validation status before claiming exploitability
- For IIS short-name: demonstrate the enumerated name maps to a sensitive resource
