---
name: drupal
description: Drupal attack surface: Drupalgeddon family, JSON:API, twig SSTI, default modules
depends_on: []
---

# Drupal

Drupal has a history of high-severity CVEs (Drupalgeddon 1/2/3). JSON:API (Drupal 8+) provides extensive resource access — frequently misconfigured.

## Common Bug Classes

- Drupalgeddon-class deserialization in legacy Drupal 7/8
- JSON:API endpoints exposing fields without permission
- Twig SSTI in custom templates
- Default `/CHANGELOG.txt` and `/MAINTAINERS.txt` for version detection
- Admin site at `/user`, `/admin/` with weak password

## Version Detection & CVE Matching

Drupal version detection is the first priority — outdated Drupal is known-CVE bingo:

```
# Primary version fingerprints
/CHANGELOG.txt           # Contains exact version: "Drupal 7.98"
/core/CHANGELOG.txt      # Drupal 8+
/INSTALL.txt             # Installation notes with version hints
/core/INSTALL.txt        # Drupal 8+
/MAINTAINERS.txt         # Contributor list with version

# Meta tag fingerprint
<meta name="Generator" content="Drupal 7 (https://www.drupal.org)">

# CSS/JS aggregation includes version hash
/sites/default/files/css/*.css
/core/misc/drupal.js     # Contains Drupal.VERSION
```

**CVE checklist by version range:**
- Drupal 7.x < 7.58: CVE-2018-7600 (Drupalgeddon 2) — RCE via Form API
- Drupal 8.x < 8.5.1: CVE-2018-7600 (Drupalgeddon 2) — RCE
- Drupal 8.x < 8.6.10: CVE-2019-6340 — REST module RCE
- Drupal < 9.3.3: Various deserialization and access bypass

## Default Endpoint Enumeration

Every Drupal installation ships well-known routes that leak data:

```
# User enumeration
/?q=user/1              # Drupal 7: user profile
/user/1                 # Drupal 8+: user profile
/user/1/edit            # Admin check: returns 403 vs 404
/?q=user/password       # Password reset form (username enumeration)
/admin/people           # User list (if accessible)

# JSON:API enumeration (Drupal 8+)
/jsonapi/                                # API root (lists all resources)
/jsonapi/node/article                    # Content nodes
/jsonapi/user/user                       # User entities
/jsonapi/node/article?filter[uid.id]=1   # Filtered queries
/jsonapi/taxonomy_term/tags              # Taxonomy terms

# REST module (Drupal 8+)
/node/1?_format=json                     # JSON representation
/node/1?_format=hal_json                 # HAL+JSON with relations
/entity/user/1?_format=json              # User entity

# Status/install paths
/core/install.php        # Installation wizard (takeover if accessible)
/install.php             # Drupal 7 install
/update.php              # Update script
/cron.php                # Cron runner
/xmlrpc.php              # XML-RPC (if enabled)
```

## Search & Reflection XSS

Drupal search and similar CMS surfaces are reliable XSS sources:

- `/search/node/<payload>` — search results reflecting input
- `/node/{id}/edit` — edit forms with pre-filled fields
- Drupal Views with exposed filters reflecting user input
- Custom block content rendered without proper escaping

## Third-Party Module Vulnerabilities

Drupal's contrib module ecosystem is a goldmine for legacy deployments:

**Audit-by-grep methodology for PHP CMS:**
```bash
# Direct variable interpolation in SQL
grep -rn "\$_GET\|\$_POST\|\$_REQUEST" modules/
grep -rn "db_query.*\\\$" modules/      # Drupal 7 db_query with interpolation
grep -rn "->condition.*\\\$" modules/   # Drupal 8 query builder

# Unsafe output
grep -rn "print.*\\\$_\|echo.*\\\$_" modules/
grep -rn "Markup.*\\\$" modules/        # Drupal render with unescaped markup

# File operations
grep -rn "file_get_contents\|fopen\|include\|require" modules/
```

**Module enumeration:**
- Probe `/modules/contrib/<module_name>/` for installed contrib modules
- Check `/sites/all/modules/` (Drupal 7 style)
- Review `/core/modules/` for enabled core modules
- Cross-reference discovered modules against Drupal security advisories

## Guard Idiom Detection

Look for missing guard patterns: Drupal 7 files need `if (!defined('DRUPAL_ROOT')) exit;` at top. Direct file access to `.module`, `.inc`, `.install` files without the guard can expose PHP source or trigger path-revealing errors.

## Plugin & Theme File Discovery

Hunt bundled demo/example files that are installed but not hardened:

```
# Common vulnerable paths
/sites/all/modules/<module>/test/
/sites/all/modules/<module>/examples/
/sites/all/themes/<theme>/demo/
/libraries/<library>/test/
/libraries/<library>/examples/

# CKEditor/WYSIWYG paths
/sites/all/libraries/ckeditor/samples/
/core/assets/vendor/ckeditor/samples/
```

## Sanitization Pipeline Audit

Drupal uses a multi-step sanitization pipeline. Audit each filter:

1. List every filter in the text format pipeline (Basic HTML, Full HTML, Restricted)
2. Check ordering: a filter that adds markup AFTER a sanitizer bypass the sanitizer
3. Test `<object>`, `<embed>`, `<svg>`, `<math>` tags in each text format
4. Verify the same input is sanitized identically in node view, search results, RSS, and REST output

## Probe Targets

- Probe `/CHANGELOG.txt`, `/INSTALL.txt`, `/core/CHANGELOG.txt`
- Crawl `/jsonapi/`, `/jsonapi/node/article`, `/jsonapi/user/user`
- Test `?_format=hal_json`, `?_format=json`
- Enumerate users via `/user/1`, `/user/2`, etc.
- Check `/core/install.php` and `/update.php` accessibility
- Probe `/xmlrpc.php` for XML-RPC methods
- Test search paths for XSS: `/search/node/<script>`
- Check `/sites/default/files/` for directory listing

## Cross-References

`api_security`, `insecure_deserialization`, `ssti`, `information_disclosure`, `cms_security`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
- For Drupalgeddon: confirm the exact version is in the vulnerable range before claiming RCE
- For JSON:API exposure: demonstrate access to data that should require authentication
