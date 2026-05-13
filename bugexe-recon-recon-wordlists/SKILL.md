---
name: Recon Wordlists Reference
category: reconnaissance
description: Wordlist selection guide — fuzz4bounty, SecLists, Assetnote, and target-aware custom wordlist generation
depends_on: []
---

# Recon Wordlists Reference

## When to Use
- Before running ffuf/dirsearch/feroxbuster — select the RIGHT wordlist
- When generic wordlists produce too many false positives
- When you need tech-specific path enumeration

## Wordlist Sources (Priority Order)

### 1. Target-Aware Custom Wordlists (BEST — build from the target itself)

```bash
# Build from historical URLs (gau/waybackurls/waymore output)
cat all_historical.txt | unfurl -u paths | sed 's|^/||' | sort -u > wordlist_historical.txt

# Build from JS bundle analysis
grep -rohP '["'"'"'][/][a-zA-Z0-9_/\-\.]+["'"'"']' js_download/ | tr -d '"'"'"'' | \
  sed 's|^/||' | sort -u > wordlist_js.txt

# Merge into master target-aware wordlist
cat wordlist_historical.txt wordlist_js.txt | sort -u > wordlist_target.txt
```

### 2. fuzz4bounty (curated for bug bounty)

Repository: `https://github.com/0xPugal/fuzz4bounty`

Location: `/usr/share/wordlists/fuzz4bounty/` or `/tmp/fuzz4bounty/`

```
fuzz4bounty/
├── discovery/
│   ├── api.txt              # API endpoint paths
│   ├── admin.txt            # Admin panel paths
│   └── ...
├── directory/
│   └── dicc.txt             # General directory discovery
├── fuzzing/                  # Fuzzing payloads (XSS, SQLi, etc.)
├── technologies/             # Tech-specific wordlists
├── DNS/                      # Subdomain wordlists
└── nuclei-wordlist/          # Nuclei template paths
```

Install if not available:
```bash
git clone https://github.com/0xPugal/fuzz4bounty /tmp/fuzz4bounty
```

### 3. Assetnote Wordlists (auto-generated from real targets)

Assetnote generates wordlists from HTTP Archive data — paths that ACTUALLY exist on real websites.

```
/opt/wordlists/assetnote/
├── httparchive_php_2024.txt                    # PHP-specific
├── httparchive_aspx_asp_cfm_svc_ashx_asmx.txt  # .NET-specific
├── httparchive_jsp_jspa_do_action.txt           # Java-specific
├── httparchive_directories_1m.txt               # Top 1M directories
└── httparchive_parameters_top25k.txt            # Top 25K parameter names
```

Download: `https://wordlists.assetnote.io/`

### 4. SecLists (industry standard)

```
/usr/share/seclists/Discovery/Web-Content/
├── api/
│   └── api-endpoints.txt           # ~500 common API paths
├── raft-medium-directories.txt      # ~30K directories
├── raft-medium-files.txt            # ~17K filenames
├── burp-parameter-names.txt         # ~6K parameter names
├── spring-boot.txt                  # Spring Boot actuator paths
├── CGIs.txt                         # CGI scripts
├── PHP.fuzz.txt                     # PHP-specific paths
└── IIS.fuzz.txt                     # IIS-specific paths
```

### 5. Fallback (always available)

```
/usr/share/wordlists/dirb/common.txt           # ~4.6K general paths
/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt  # ~87K
```

## Tech → Wordlist Decision Matrix

Detected tech stack determines which wordlist to use:

```
PHP detected:
  Primary:   fuzz4bounty/technologies/php.txt
  Secondary: seclists/PHP.fuzz.txt + assetnote/php
  Extensions: .php,.phtml,.inc,.bak

Node.js / Express:
  Primary:   seclists/api/api-endpoints.txt
  Secondary: assetnote/nodejs + custom JS-extracted paths
  Extensions: .js,.json,.mjs

Java / Spring Boot:
  Primary:   seclists/spring-boot.txt
  Secondary: assetnote/jsp + fuzz4bounty/technologies/java.txt
  Extensions: .jsp,.do,.action,.json

Python / Django / Flask:
  Primary:   seclists/api/api-endpoints.txt + django-specific
  Secondary: custom paths from historical URLs
  Extensions: .py,.json,.yaml

.NET / ASP:
  Primary:   assetnote/aspx + seclists/IIS.fuzz.txt
  Secondary: fuzz4bounty/technologies/aspnet.txt
  Extensions: .aspx,.ashx,.asmx,.config

Ruby / Rails:
  Primary:   seclists/api/api-endpoints.txt + rails-specific
  Extensions: .rb,.json,.html.erb

WordPress:
  Primary:   seclists/CMS/wordpress.fuzz.txt
  Secondary: wp-content/plugins/ + wp-content/themes/ enum
  Extensions: .php,.txt,.bak

Generic API (no framework detected):
  Primary:   seclists/api/api-endpoints.txt
  Secondary: fuzz4bounty/discovery/api.txt
  Tertiary:  target-aware custom wordlist
```

## ffuf Quick Reference

```bash
# Basic directory discovery
ffuf -u "$TARGET/FUZZ" -w WORDLIST -mc 200,301,302,401,403 -t 50

# With extensions
ffuf -u "$TARGET/FUZZ" -w WORDLIST -e .php,.json,.bak,.env -mc 200,301,403

# Filter by response size (remove false positives)
ffuf -u "$TARGET/FUZZ" -w WORDLIST -fs 1234 -mc all

# Recursive (depth 2)
ffuf -u "$TARGET/FUZZ" -w WORDLIST -recursion -recursion-depth 2 -mc 200,301,403

# Parameter fuzzing
ffuf -u "$TARGET/api/endpoint?FUZZ=test" -w burp-parameter-names.txt -mc 200 -fs 0

# POST body fuzzing
ffuf -u "$TARGET/api/endpoint" -w WORDLIST -X POST \
  -H "Content-Type: application/json" -d '{"FUZZ":"test"}' -mc 200,401,403,500
```

## Key Principle

The best wordlist is the one built from the target itself. Historical URLs + JS extraction produce a small, high-accuracy wordlist that outperforms any generic 100K-entry list.
