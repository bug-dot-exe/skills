---
name: recon_vhost_fuzzing
category: reconnaissance
description: Virtual-host fuzzing — same IP, different Host headers reveal hidden apps invisible to DNS. Covers HTTP/1.1, HTTP/2, HTTP/3 authority fuzzing, TLS SNI fuzzing, header bypass tricks (port suffix, URL-encoded dots, duplicate Host, absolute URI, X-Forwarded-Host / X-Original-URL), per-port multiplexing (80/443/8080/8443/8000/8081/8888/9000/9090/3000/5000), and baseline-vs-candidate response clustering. Composes with subdomain enumeration, permutation, ASN mapping, and information disclosure skills.
depends_on: []
---

# Virtual-Host Fuzzing

## Why VHost Fuzzing Matters

A web server may host dozens of distinct applications behind the same IP and port. Each one is selected by the `Host:` header in HTTP/1.1 (or `:authority` in HTTP/2 / HTTP/3, or by SNI in TLS). When a request arrives without a matching Host, the server falls back to a default vhost — sometimes a public marketing site, sometimes a 404, sometimes a generic 421 Misdirected Request.

The interesting class of finding: an application that has **no public DNS record**. It exists, accepts requests, but is only reachable when you already know to ask for it by name. These are the staging sites, internal tooling instances, partner-only portals, employee dashboards, legacy beta apps, and decommissioned-but-still-listening services that organizations forget about. They commonly run with weaker authentication, debug mode enabled, default credentials, or unhardened configs.

DNS enumeration alone misses them entirely. Even passive sources like crt.sh only catch them if a TLS certificate was issued under a domain that resolves publicly. A company can mint an internal certificate, deploy an app, never publish DNS, and the only way to find it is to know the right Host header value to send.

The technique is mechanical. Identify candidate IPs that host web services. For each IP, pick a known-bogus Host as a baseline. Then iterate through Host candidates and compare each response against the baseline. Distinct response = real vhost. Cluster the responses, manually inspect any cluster that diverges from the baseline, and you have a list of hidden applications.

## Detection Methodology

The methodology has five steps. Each is dependent on the prior step.

### Step 1: Identify candidate IPs

VHost fuzzing operates per-IP, not per-domain. Before fuzzing, build the IP set:

- Resolve every known subdomain (chain to `recon_subdomain_active_brute` and `recon_passive_subdomain` outputs)
- Walk the ASN(s) of the organization (chain to `recon_asn_network_mapping`)
- Pull all IPs that are confirmed to host a TCP listener on common HTTP ports (chain to `recon_port_service_analysis`)
- Filter out CDN-fronted IPs unless explicitly in scope — a CDN edge IP serves thousands of unrelated tenants and vhost fuzzing it is meaningless

Group IPs by likely web-server family if banners are available (nginx vs Apache vs IIS vs Caddy vs custom). The bypass tricks differ per server.

### Step 2: Establish baseline response

For each IP and each web port, send a request with a Host header that cannot exist:

```
Host: nonexistent-{random}-{random}.invalid
```

Record:

- HTTP status code
- `Content-Length` (or actual body byte count)
- A hash (sha256 of the body, truncated to 12 chars is enough)
- The `Server:` header
- The full set of response headers
- Whether the server returned a TLS certificate, and if so, the certificate's SAN list

This baseline is the "default vhost" response. It is what every Host header that does NOT match a configured vhost will return. Some servers return 421 Misdirected Request. Some return the marketing page. Some return a 404. Some return a generic upstream error. The point is: the baseline is the noise, and any candidate Host whose response differs from the baseline is signal.

If the same IP serves both port 80 and port 443, baseline both separately — they may be different applications.

### Step 3: Iterate Host candidates

For each candidate Host name, send a request with that Host and compare the response signature against the baseline.

Candidate sources, in priority order:

1. Every subdomain from passive enumeration
2. Every subdomain from active brute-force
3. Every permutation generated from known subdomains
4. Common internal-app names (see candidate list below)
5. Cloud-native names tied to the IP's provider (e.g., if the IP is in AWS, try `*.elb.amazonaws.com` style names)

Candidate Host header request:

```
GET / HTTP/1.1
Host: {candidate}
User-Agent: {agent}
Accept: */*
Connection: close
```

For each candidate, record the same fields as the baseline. Compute the diff:

- Status code different from baseline → strong signal
- Body hash different from baseline → strong signal
- `Content-Length` different from baseline by more than ~5% → moderate signal
- `Server:` header different → moderate signal
- New cookies set, or a `Set-Cookie` with a session ID that the baseline did not have → strong signal
- Redirect to a different URL than the baseline redirected to → strong signal
- TLS certificate's CN/SAN list different (when fuzzing TLS SNI) → strong signal

A response that matches the baseline exactly is "default vhost" — that candidate Host is not configured on this IP. A response that diverges is a real vhost.

### Step 4: Cluster results

After all candidates have been probed, group them by response signature. Patterns that emerge:

- A cluster of dozens of candidates all sharing the baseline signature → all default-vhost'd, no signal
- A cluster of 5-10 candidates sharing a non-baseline signature → likely the same internal app served under multiple aliases
- A singleton cluster (one candidate, one unique signature) → likely a unique vhost worth manual review

Investigate every non-baseline cluster manually. Visit the URL with the right Host, render the page, look at what application is actually serving.

### Step 5: Cross-reference and pivot

Every newly-discovered vhost becomes input to other recon skills:

- Feed the vhost name back into permutation generation
- Probe the vhost for information disclosure paths
- Run path/directory fuzzing against the vhost
- If the vhost responds to a well-known framework path, fingerprint the framework and pivot

## Smart VHost Candidate Sources

Cast a wide net. Below are candidate categories, in rough priority of yield.

### From passive subdomain enumeration

Every subdomain pulled from CT logs, search engines, archive sources, third-party APIs, and historical DNS. Even subdomains that no longer resolve in DNS may still have a vhost configured on the IP. Test all of them.

### From permutations of known subdomains

Chain to `recon_subdomain_permutations`. Take every confirmed subdomain and feed permutations as Host candidates against every web-port IP. The permutation engine generates internal-flavored variants (`dev-`, `staging-`, `int-`, `lb-`, `api-`) that may exist as vhosts but never as DNS entries.

### Common internal-app names

A short reusable list of names that appear in nearly every organization's internal infrastructure:

```
# Authentication / identity
admin auth sso oauth login internal-login console panel manage manager mgmt

# Internal-only audiences
internal intranet staff employee partner vendor supplier customer-internal

# API tiers
api api-internal api-staging api-dev api-test api-qa api-uat api-v1 api-v2 graphql backend

# Build / CI / artifact
ci jenkins gitlab gitea bitbucket teamcity drone harbor nexus artifactory registry docker

# Issue tracker / docs
jira confluence wiki sonar codeclimate sentry rollbar

# Telemetry / observability
splunk elk kibana grafana prometheus alertmanager loki jaeger zipkin datadog newrelic dynatrace pagerduty

# Secret / config / orchestration
vault consul nomad etcd zookeeper rancher openshift k3s flux argo argocd spinnaker

# Data / messaging
kafka rabbitmq redis memcached mongo postgres mysql mariadb mssql oracle elasticsearch opensearch clickhouse

# Analytics / BI / ML
metabase superset redash airflow jupyter mlflow kubeflow ray spark

# Network / proxy / gateway
kong tyk apigee envoy traefik haproxy nginx-status apache-status varnish proxy squid

# Storage / file
upload uploads files fs storage minio backup snapshot archive

# Lifecycle / environment
dev develop staging stg test qa uat sit preprod prelive preview canary blue green legacy old new beta alpha demo sandbox playground

# Versioned hosts
v1 v2 v3 latest stable

# Numbered nodes
node1 node2 node3 srv1 srv2 server1 worker1 worker2 host1 host2

# Operations / status
ops sre infra platform health status monitor metric trace log audit dashboard

# Communication
mail smtp imap pop3 exchange chat slack mattermost rocketchat

# HR / finance / business
hr hris ats finance billing accounting erp crm support helpdesk ticketing

# Cloud-flavored
lb-internal internal-lb origin edge core gateway service microservice batch job scheduler queue
```

This list is reusable across organizations. Augment it with org-specific terminology pulled from job listings, blog posts, and engineering pages — but the generic core above will hit on most orgs.

### Cloud-specific candidates

When the candidate IP belongs to a cloud provider, add cloud-flavored Hosts:

- AWS ELB: `*.us-east-1.elb.amazonaws.com`, `internal-*.elb.amazonaws.com`, `*.us-west-2.elb.amazonaws.com`
- AWS ALB: `*.us-east-1.alb.amazonaws.com`, internal ALB DNS
- AWS API Gateway: `*.execute-api.us-east-1.amazonaws.com`
- AWS S3 website: `*.s3-website-us-east-1.amazonaws.com`, `*.s3.amazonaws.com`
- GCP LB: `*.googleusercontent.com`, `*.appspot.com`, `*.run.app`
- GCP Cloud Run: `*-{hash}-uc.a.run.app`
- Azure: `*.azurewebsites.net`, `*.cloudapp.azure.com`, `*.azureedge.net`
- DigitalOcean App Platform: `*.ondigitalocean.app`
- Heroku: `*.herokuapp.com`
- Vercel: `*.vercel.app`
- Netlify: `*.netlify.app`
- Render: `*.onrender.com`
- Fly.io: `*.fly.dev`
- Railway: `*.railway.app`

The rationale: a misconfigured load balancer may route requests bound for the public DNS through to backend services that are addressable only by their cloud-native hostname.

## TLS SNI Fuzzing

For HTTPS, the server selects the certificate (and often the backend) based on the SNI extension in the TLS ClientHello — not the HTTP Host header. This means SNI fuzzing must complement Host fuzzing.

### Procedure

1. Connect to the IP on port 443 with a candidate SNI value
2. Record the certificate returned (CN, SAN list, issuer, notBefore, notAfter, fingerprint)
3. Compare against a baseline (connect with bogus SNI — server returns default cert or no cert)
4. A different cert returned per SNI = a different vhost is configured

Example:

```
openssl s_client -connect {ip}:443 -servername {candidate-sni} -showcerts < /dev/null
```

The cert returned is the strongest single signal that a vhost exists. Even if the HTTP layer returns a generic 404, a unique cert proves the vhost is provisioned.

### What to do with the cert

- Add every name in the SAN list as a new vhost candidate
- Mine the cert's issuer for org-specific naming patterns
- If the cert is internal-CA-issued, the SAN list is gold — these are names that were never published to public CT logs
- Track cert renewal: if `notBefore` is recent (last 30 days), the vhost is active

### SNI-only vhosts

Some vhosts respond to SNI but not Host. To detect: connect with the candidate SNI and send the bogus baseline Host. If the response differs from the bogus-SNI bogus-Host baseline, the vhost is keyed on SNI alone.

## HTTP/2 and HTTP/3 VHost Fuzzing

In HTTP/1.1 the vhost is selected by the `Host` header. In HTTP/2 it is selected by the `:authority` pseudo-header. In HTTP/3 (QUIC) it is also `:authority`. The semantics are nearly identical, but the protocol differences matter.

### Why it matters

A server may have HTTP/2 enabled with strict authority validation, and HTTP/1.1 enabled with permissive Host handling. The same candidate name may return different responses on different protocols. Fuzz all three.

### Connection coalescing

HTTP/2 allows a client to reuse a connection across origins if the certificate is valid for both names. This means a candidate Host probe over HTTP/2 may accidentally hit a different vhost than expected because the connection was coalesced. To avoid: use a single connection per candidate, or disable connection reuse in the client.

### Common probe forms

```
# HTTP/1.1 Host
curl -k -H "Host: {candidate}" https://{ip}/

# HTTP/2 :authority (curl picks HTTP/2 automatically when supported)
curl -k --http2 -H "Host: {candidate}" https://{ip}/

# HTTP/3
curl -k --http3 -H "Host: {candidate}" https://{ip}/
```

Some servers support all three but route differently per protocol — the same Host on HTTP/1.1 may return 404 while on HTTP/2 it returns 200.

## Bypass Tricks

Reverse proxies, load balancers, and CDNs commonly normalize the Host header in ways that hide vhost differences. The bypass tricks below exploit ambiguities in that normalization.

### Port suffix in Host

Some servers route by full host including port. A candidate vhost that does not respond to `Host: {candidate}` may respond to `Host: {candidate}:8080` or `Host: {candidate}:443`. Try a small set of port suffixes per candidate.

### URL-encoded characters in Host

`Host: target%2eexample` decodes to `Host: target.example`, but only on some servers. The server may accept the encoded form, decode it, and route as if the literal had been sent. This bypasses normalization that strips unknown vhosts. Try percent-encoding common characters: `.`, `:`, `-`, `_`.

### Multiple Host headers

HTTP/1.1 says a request must have exactly one Host header. In practice, many servers accept multiple. They differ in which one they honor:

- nginx: usually rejects, but configurable
- Apache: depends on `MergeTrailers` and version
- HAProxy: usually rejects
- Custom proxies: often honor first or last

Send two `Host:` headers. If the server processes one and the upstream backend processes the other, you can hit a vhost that the proxy is unaware of. This is also a common HTTP-request-smuggling primitive when paired with desync vectors.

### Absolute URI in request line

```
GET https://target-internal.example/path HTTP/1.1
Host: target.example
```

Per RFC, the request line's absolute URI takes precedence over the Host header. Some proxies route by the URI authority, some by the Host header. If they disagree, you can reach a vhost via the URI authority that the Host header would have blocked.

### X-Forwarded-Host / X-Forwarded-For / X-Original-URL header confusion

When the reverse proxy is behind a CDN, the CDN forwards `X-Forwarded-Host` or `X-Forwarded-Server` to the upstream. Some upstream apps trust those headers and use them for routing or content generation. Send:

```
Host: target.example
X-Forwarded-Host: target-internal.example
X-Original-URL: /
X-Rewrite-URL: /
X-Original-Host: target-internal.example
X-Host: target-internal.example
X-Forwarded-Server: target-internal.example
Forwarded: host=target-internal.example
```

If the upstream renders `target-internal.example` content while the CDN thinks it served `target.example`, the upstream vhost is reachable via header injection.

### Mixed-case Host

`HOST:`, `host:`, `Host:`, `HoSt:` — most servers normalize, some do not. Try a few permutations.

### Trailing dot in Host

`Host: target-internal.example.` (trailing dot) is FQDN-canonical. Some servers strip the dot, some treat it as a different hostname. Worth a shot per candidate.

### Whitespace in Host value

```
Host:  target-internal.example
Host:	target-internal.example
Host: target-internal.example 
```

Leading/trailing whitespace and tabs are sometimes handled inconsistently. The vhost lookup may fail (and fall back to default) on the proxy while the upstream strips whitespace and routes correctly.

## Tool Primitives

The mechanics are simple — most of the value is in the candidate generation and result clustering, not in the tool. Useful sandbox-installable primitives:

- `curl -H "Host: {candidate}" {url}` — single-shot manual probe
- `httpx -p 80,443,8080,8443 -nh -host {candidate1},{candidate2} -ip {ip}` — batch probe with diff-from-baseline filtering
- `ffuf -u http://{ip}/ -H "Host: FUZZ" -w {wordlist} -fs {baseline-size} -mc 200,301,302,401,403,500` — wordlist-driven fuzz with size-based filtering
- `gobuster vhost -u http://{ip}/ -w {wordlist}` — vhost mode
- `wfuzz -c -u http://{ip}/ -H "Host: FUZZ.target.example" -w {wordlist} --hh {baseline-size}` — alternative
- `nuclei -t http/misconfiguration/host-header-injection.yaml -u {url}` — known-pattern probes
- `openssl s_client -connect {ip}:443 -servername {sni}` — TLS SNI probe
- Ad hoc Python loop using `httpx` async client when more control is needed

A pure curl loop is often enough:

```
for candidate in $(cat candidates.txt); do
  resp=$(curl -k -s -o /dev/null -w "%{http_code} %{size_download} %{redirect_url}" \
              -H "Host: $candidate" "https://{ip}/")
  echo "$candidate $resp"
done | tee vhost-results.txt
```

Then cluster `vhost-results.txt` by the response signature column and inspect non-baseline clusters.

## Pitfalls

VHost fuzzing has well-known failure modes. Knowing them avoids wasted time.

### CDN normalization

Cloudflare, Akamai, Fastly, AWS CloudFront all normalize Host in ways that may flatten signal. If the IP is a CDN edge, every Host you send may produce the same generic CDN response and the real vhost is reachable only through a Host that the CDN knows to forward. In that case: pivot to origin-IP discovery (chain to `recon_origin_disclosure` if it exists, or use historical DNS / Censys / Shodan to find the origin).

### Wildcard SSL cert hides differences

A server with a wildcard cert (`*.target.example`) returns the same cert for every SNI under the wildcard. SNI fuzzing yields no new signal — only HTTP-layer Host fuzzing. Be aware so you do not over-trust SNI as a discriminator.

### HTTP/2 connection reuse

If you fuzz over HTTP/2 with a long-lived connection, the server may route subsequent streams based on the original `:authority` rather than the per-stream override. Use one connection per candidate when in doubt.

### Server-side caching by Host

Some servers cache by Host header. The first request to a new candidate is slow (cache miss → backend hit), the second is fast (cache hit). A slow first-byte time is a leak: it implies the server actually went upstream for that Host, which implies a real backend exists. Track per-candidate latency and flag outliers as potential vhosts even if their response matches baseline (they may be cache-warming a real backend).

### Rate limiting

Aggressive fuzzing trips WAF/IDS rate limits. Slow down (sub-1-RPS), rotate User-Agent, randomize candidate order. If you start getting 429s mid-fuzz, restart from scratch — your earlier results may have been affected by rate-limit-induced response degradation.

### Default-vhost honeypot

Some orgs configure the default vhost to look like a legitimate app to catch scanners. Treat the baseline as untrusted ground truth — re-baseline periodically with a different bogus Host to confirm the baseline is stable. If the "baseline" varies between probes, you cannot cluster reliably.

### Internal-only DNS resolves your candidate

If your test machine is somehow on the org's network (rare but possible — VPN, partner connection, etc.), a candidate Host may resolve internally. The IP under test is no longer the same as the IP your candidate's DNS resolves to. Always force the IP via `--resolve` (curl) or `Host:` header with the request going to the explicit IP, not by name.

## Output Format

For every probed (IP, port, Host candidate) tuple, record at minimum:

```
{
  "ip": "{ip}",
  "port": {port},
  "scheme": "http|https",
  "protocol": "http/1.1|h2|h3",
  "host_candidate": "{candidate}",
  "sni": "{sni-value-if-tls}",
  "response_status": {status},
  "response_size": {bytes},
  "response_hash": "{sha256-12}",
  "server_header": "{value}",
  "set_cookie_present": true|false,
  "redirect_location": "{url-if-3xx}",
  "tls_cert_cn": "{cn-if-tls}",
  "tls_cert_san": ["{san1}", "{san2}"],
  "distinct_from_baseline": true|false,
  "diff_dimensions": ["status", "size", "hash", "server", "cookie", "redirect", "cert"],
  "first_byte_latency_ms": {ms},
  "request_method": "GET|HEAD|OPTIONS",
  "request_headers_used": {"Host": "{candidate}", "X-Forwarded-Host": "{value}"}
}
```

Persist this as JSON Lines for easy clustering. Every clustering pass is a `jq | sort | uniq -c` away.

## Composes With

- `recon_subdomain_permutations` — feeds Host candidates
- `recon_passive_subdomain` — feeds Host candidates
- `recon_subdomain_active_brute` — feeds Host candidates
- `recon_port_service_analysis` — identifies which ports per IP host HTTP listeners
- `recon_asn_network_mapping` — identifies which IPs to probe in the first place
- `recon_information_disclosure` — newly-discovered vhosts get path-fuzzing and disclosure probes
- `recon_origin_disclosure` (if exists) — when the IP is CDN, pivot to origin first
- `js_analysis` and `js_runtime_audit` — JS bundles on a public app may reference internal vhost names

Any vhost finding is a recon seed. Re-feed the new name into permutation, brute, and crawl.

## Termination

VHost fuzzing terminates when the **full Host candidate space** has been exhausted against the **full IP × port × protocol matrix**, not when "we found N vhosts."

Concretely:

- Per IP: probe every web port (80, 443, 8080, 8443, 8000, 8081, 8082, 8888, 8889, 9000, 9090, 9091, 3000, 3001, 4000, 5000, 5001, 5555, 7000, 7001, 7777, 7000-7010, 50000-50010 if non-standard ports were observed by port scan)
- Per port: probe every protocol the listener advertises (HTTP/1.1, HTTP/2, HTTP/3 if QUIC is up)
- Per (IP, port, protocol): probe every candidate Host
- Per (IP, port, protocol): probe every candidate SNI for HTTPS
- Per discovered vhost: re-feed the name through permutations and re-probe

There is no "we have enough" exit clause. The cost of an extra probe is one request. The cost of a missed internal app is the entire finding. Always iterate to exhaustion and then iterate again with the newly-discovered names as new seeds.

When the exhaustion check returns "no new vhosts in the last full pass," the loop is done. Until then, continue.
