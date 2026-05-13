---
name: wordpress
description: Security testing playbook for WordPress covering admin access, XML-RPC, plugin/theme vulnerabilities, user enumeration, and REST API exposure
depends_on: []
---

# WordPress

Security testing for WordPress installations. Focus on wp-admin access, xmlrpc.php brute force and SSRF, plugin/theme vulnerability discovery, user enumeration, REST API exposure, wp-config.php leakage, and media upload abuse.

## Attack Surface

**Core WordPress**
- `wp-login.php`: authentication endpoint, brute force target
- `xmlrpc.php`: XML-RPC interface for pingbacks, auth, multicall batching
- `wp-cron.php`: pseudo-cron for scheduled tasks
- `wp-config.php`: database credentials, auth keys/salts, debug settings, table prefix

**Admin Panel**
- `/wp-admin/`: dashboard, plugin/theme editor, user management, options
- `/wp-admin/admin-ajax.php`: AJAX handler for logged-in and nopriv actions
- `/wp-admin/admin-post.php`: POST handler for custom actions

**REST API**
- `/wp-json/wp/v2/`: users, posts, pages, comments, media, settings
- Custom REST routes from plugins/themes
- Application Passwords (WP 5.6+)

**Plugins & Themes**
- `/wp-content/plugins/`: active and inactive plugin directories
- `/wp-content/themes/`: active and parent/child theme directories
- Plugin AJAX handlers via `wp_ajax_` and `wp_ajax_nopriv_` hooks
- Shortcode handlers, REST API extensions, custom post types

**File System**
- `/wp-content/uploads/`: media library, year/month subdirectories
- `/wp-content/debug.log`: debug output when WP_DEBUG_LOG is enabled
- `/wp-includes/`: core library files
- `.htaccess`, `web.config`: server configuration

## High-Value Targets

- `/wp-login.php` - brute force, credential stuffing, password reset
- `/xmlrpc.php` - amplified brute force, SSRF via pingback, DoS
- `/wp-config.php` - direct access or via backup/editor exposure
- `/wp-content/debug.log` - debug output with sensitive errors
- `/wp-json/wp/v2/users` - user enumeration (usernames, slugs, IDs)
- `/wp-admin/theme-editor.php` and `/wp-admin/plugin-editor.php` - direct code editing
- `/wp-content/uploads/` - uploaded files, potentially executable
- `/.wp-config.php.swp`, `/wp-config.php.bak`, `/wp-config.php~` - backup files

## Reconnaissance

**Version Detection**
```
GET /readme.html
GET /license.txt
GET /wp-includes/version.php
```
Meta generator tag: `<meta name="generator" content="WordPress X.X.X" />`
RSS feed: `/feed/` contains generator version.

**User Enumeration**
```
GET /?author=1                    # Redirects to /author/username/
GET /?author=2                    # Iterate through IDs
GET /wp-json/wp/v2/users          # JSON list of users
GET /wp-json/wp/v2/users?per_page=100
GET /?rest_route=/wp/v2/users     # Alternate REST path
```
- Author archive redirects reveal usernames from user IDs
- REST API returns usernames, display names, avatar URLs, user descriptions
- Login error messages: "Invalid username" vs "Incorrect password" differentiates existence

**Plugin/Theme Enumeration**
```
GET /wp-content/plugins/plugin-name/readme.txt
GET /wp-content/plugins/plugin-name/changelog.txt
GET /wp-content/themes/theme-name/style.css
```
- Readme files contain version numbers for vulnerability matching
- Source code reveals `Stable tag:`, `Version:`, `Tested up to:`
- Aggressive scan: probe top 1000 plugin slugs from WPScan database

**Configuration Exposure**
```
GET /wp-config.php
GET /wp-config.php.bak
GET /wp-config.php.old
GET /wp-config.php.save
GET /wp-config.php.swp
GET /wp-config.php~
GET /wp-config.txt
GET /.env
GET /wp-content/debug.log
```

## Key Vulnerabilities

### XML-RPC Abuse

**Brute Force via system.multicall**
```xml
POST /xmlrpc.php
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value>wp.getUsersBlogs</value></member>
      <member><name>params</name><value><array><data>
        <value>admin</value><value>password1</value>
      </data></array></value></member>
    </struct></value>
    <!-- Repeat with different passwords -->
  </data></array></value></param></params>
</methodCall>
```
- Single HTTP request tests hundreds of credentials
- Bypasses rate limiting applied to wp-login.php
- `wp.getUsersBlogs`, `wp.getAuthors`, `wp.getPosts` require valid credentials

**SSRF via Pingback**
```xml
POST /xmlrpc.php
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value>http://internal-service:8080/</value></param>
    <param><value>https://target.com/existing-post</value></param>
  </params>
</methodCall>
```
- WordPress makes an HTTP request to the first URL (sourceUrl)
- Can reach internal services, cloud metadata endpoints
- Port scanning and service discovery via response timing/errors

**DoS via Pingback Amplification**
- Flood target with pingback requests, each triggering an outbound HTTP request
- Used for reflected DDoS amplification

### Plugin/Theme Vulnerabilities

**Common Plugin Bug Classes**
- SQL injection in custom database queries (direct `$wpdb->query()` without `$wpdb->prepare()`)
- Cross-site scripting in admin pages, shortcode output, AJAX responses
- Arbitrary file upload via plugin-specific upload handlers
- Local file inclusion through template/file loading with user input
- Authentication bypass in custom login/registration flows
- Privilege escalation via unprotected AJAX actions
- Object injection via `unserialize()` on user-controlled data

**High-Risk Plugin Patterns**
```
wp_ajax_nopriv_{action}    # AJAX handler accessible without login
add_action('init', ...)     # Custom handlers on init (no auth check)
$_GET/$_POST used directly  # Missing sanitization/escaping
include($user_input)        # File inclusion
```

**Theme Vulnerabilities**
- Arbitrary file upload via theme options
- XSS in custom theme settings pages
- Backdoors in nulled/pirated themes
- `functions.php` with custom AJAX handlers lacking nonce/capability checks

### REST API Exposure

**User Data**
- `/wp-json/wp/v2/users` returns usernames by default (WordPress 4.7+)
- User descriptions, registered dates, avatar URLs
- Custom user meta exposed by plugins extending REST response

**Content Access**
- Draft posts/pages accessible via REST API with improper permission checks
- Private post types exposed by poorly coded custom endpoints
- Media library enumeration: `/wp-json/wp/v2/media`

**Application Passwords**
- WP 5.6+: per-user API keys for REST authentication
- Stored as user meta; compromised admin can create silent API access
- Missing revocation UI or audit trail in default WP

### wp-config.php Exposure

**Impact**
- Database credentials: DB_NAME, DB_USER, DB_PASSWORD, DB_HOST
- Authentication keys/salts: used for cookie signing and session security
- `$table_prefix`: enables targeted SQL injection if prefix is known
- Debug settings: WP_DEBUG, WP_DEBUG_LOG, WP_DEBUG_DISPLAY
- Custom constants: API keys, paths, feature flags

**Access Vectors**
- Backup files left by editors or deployment scripts
- PHP processing failure (misconfigured server returns raw PHP)
- Version control exposure (`.git/` accessible)
- Server-side include or LFI via vulnerable plugin

### Admin Panel Exploitation

**Brute Force**
- wp-login.php with no default rate limiting or lockout
- Credential stuffing with enumerated usernames
- Password reset flow: timing/response differences for valid vs invalid emails

**Code Execution via Editors**
- Theme Editor (`/wp-admin/theme-editor.php`): edit PHP files of active theme
- Plugin Editor (`/wp-admin/plugin-editor.php`): edit any installed plugin
- Inject PHP backdoor into theme's `functions.php` or unused template file

**Plugin Upload**
- Upload malicious plugin as ZIP via `/wp-admin/plugin-install.php`
- Plugin needs only a valid header comment; code executes on activation
- Theme upload similarly allows code execution

### File Upload via Media

**Upload Restrictions**
- WordPress checks MIME type and extension against allowlist
- Bypass: double extensions (`.php.jpg`), MIME type spoofing, `.phtml`, `.php5`
- SVG upload (if enabled): stored XSS via SVG with JavaScript
- `.htaccess` upload in `/wp-content/uploads/` to enable PHP execution

**Path Traversal**
- Custom upload handlers in plugins may not sanitize filenames
- Year/month directory structure predictable for enumeration

### Database Prefix Information

**$table_prefix Impact**
- Default `wp_` enables generic SQL injection payloads
- Custom prefix requires discovery but significantly reduces attack complexity once known
- Exposed in: wp-config.php, error messages, REST API responses (plugin-dependent)

## Bypass Techniques

- xmlrpc.php multicall to bypass per-request rate limiting on wp-login.php
- REST API alternate path: `/?rest_route=/wp/v2/users` when `/wp-json/` is blocked
- Author enumeration via `?author=N` redirect even when REST API is restricted
- Plugin-specific AJAX with `wp_ajax_nopriv_*` actions bypassing admin authentication
- Content-type switching on REST API endpoints
- Cookie-based auth on REST API without nonce (Application Passwords vs cookie auth)

## Testing Methodology

1. **Fingerprint** - Detect WordPress version, enumerate users, plugins, themes
2. **XML-RPC** - Test multicall brute force, pingback SSRF, method enumeration
3. **REST API** - Enumerate users, check for exposed drafts/private content, custom endpoints
4. **Plugin audit** - Match installed plugins against vulnerability databases (WPScan, Patchstack)
5. **Config exposure** - Probe for wp-config backups, debug.log, .env files
6. **Admin access** - Brute force login, test password reset flow, check editor/upload access
7. **File upload** - Test media upload restrictions, extension/MIME bypass, SVG XSS
8. **AJAX handlers** - Enumerate `wp_ajax_nopriv_*` actions for unauthenticated access

## Corpus-Derived Attack Patterns

### Plugin AJAX SQLi Pipeline
Highest-yield WordPress-specific bug class ($4,500+ per finding). Systematic approach:
1. Enumerate all `wp_ajax_nopriv_*` action hooks (unauthenticated AJAX handlers)
2. For each handler, trace parameter flow from `$_GET`/`$_POST` to database queries
3. Look for `$wpdb->query()` or `$wpdb->get_results()` WITHOUT `$wpdb->prepare()`
4. Integer-context SQLi: when parameter is numeric, skip quote payloads entirely -- use `1 AND SLEEP(5)` or `1 UNION SELECT` directly
5. Test `wp_ajax_*` (authenticated) handlers with subscriber-level accounts -- many lack `current_user_can()` checks

### Batch/Multicall Defense Bypass
Beyond brute force, any WordPress endpoint with per-request rate limiting or WAF rules is vulnerable to multicall amplification:
- `system.multicall` wraps N operations in a single HTTP request, bypassing request-counting defenses
- Extends to any plugin exposing XML-RPC methods: enumerate with `system.listMethods`
- DoS amplification: single request triggering N internal operations (database queries, API calls, email sends)
- Test whether WAF rules count the outer request or inner method calls

### REST API Permission Split
When WordPress has both list/search and direct-read endpoints for the same resource:
- Test if search/filter endpoints enforce ACLs that direct GET-by-ID endpoints skip
- Custom post types registered with `show_in_rest` may expose private data via `/wp-json/wp/v2/{type}`
- Plugin REST routes often implement list-level permissions but skip per-item checks
- Probe with `?context=edit` parameter which requests additional fields (requires auth but may leak on misconfigured endpoints)

### Marketplace Plugin Trust Gap
WordPress plugins that integrate with external platforms (Jira, Slack, Salesforce, etc.) create delegation gaps:
- Plugin configuration pages may check WordPress admin role but not validate the user has permissions in the external platform
- JWT/OAuth tokens stored in WordPress options table accessible to any admin
- Integration webhook receivers often lack signature verification -- test callback URLs with crafted payloads
- Plugin-to-plugin trust: one plugin assumes another's authentication without re-verifying

### Filter Pipeline Differential
WordPress content flows through multiple filter pipelines (Markdown to HTML, sanitization, shortcode expansion):
- Each filter is independently bypassable -- test what one filter allows that another fails to catch
- Shortcode injection: `[shortcode attr="javascript:alert(1)"]` where plugin shortcodes render attributes into HTML
- Parser differential between editor allowlist and frontend rendering engine
- `wp_kses_post()` allowlist may permit elements that become XSS vectors when combined with specific themes

### Third-Party Subdomain XSS
Large WordPress deployments often have forgotten subdomains running outdated WordPress:
- Search parameters (`?s=`, `?q=`, `?search=`, `?query=`, `?filter=`) on legacy subdomains often lack output encoding
- `?city=`, `?country=`, `?type=`, `?category=` filter parameters in older WordPress themes are reflected XSS candidates
- Third-party WordPress instances in program scope may be unmaintained with known CVEs
- Test REST API alternate path `/?rest_route=/wp/v2/users` when `/wp-json/` is WAF-blocked

### Open-Core/Plugin Permission Boundary
WordPress multisite and plugin ecosystems have fragmented permission models:
- Functions hooked via `prepend_filter` or plugin decorators may bypass the permission check of the function they extend
- Capability checks in free plugin version may be absent in premium add-on code paths
- `switch_to_blog()` in multisite: verify capability checks use the target blog's context, not the source
- Custom capabilities registered by plugins may not be assigned to any role by default, creating "orphan permissions" testable via direct function calls

## Validation Requirements

- XML-RPC brute force: successful authentication via multicall demonstrating bypass of login rate limits
- User enumeration: usernames retrieved via author archive or REST API
- Plugin vulnerability: exploitation of specific CVE with version confirmation from readme.txt
- wp-config exposure: database credentials or auth keys retrieved from config or backup file
- REST API: access to unauthorized content (drafts, private posts, user data)
- Admin RCE: code execution via theme/plugin editor or malicious plugin upload
- File upload bypass: executable file uploaded and accessed via media URL
- SSRF via pingback: server-side request to internal endpoint confirmed via timing or response
