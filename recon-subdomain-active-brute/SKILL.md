---
name: recon-subdomain-active-brute
category: reconnaissance
description: Active DNS brute-force enumeration — generate candidate names and resolve them. Covers wordlist strategy (universal short, long-tail, org-tuned, source-derived), resolution primitives (dnsx, puredns, massdns, subfinder), wildcard detection and validation, resolver hygiene (rotation, trusted lists, rate self-throttling), recursive expansion, and HTTP-probe validation. Composes with passive subdomain, permutation, vhost fuzzing, and ASN mapping skills.
depends_on: []
---

# Active Subdomain Brute-Force

## Why Active Brute-Force Matters

Passive subdomain sources — certificate transparency logs, search-engine scrapes, third-party DNS aggregators, archive.org, Shodan/Censys — return only names that have already leaked into a public dataset. They miss every name that has been provisioned but never indexed: anything created since the last crawl, anything that never resolved on a public resolver, anything behind split-horizon DNS, and anything generated programmatically that humans have not yet typed into a browser.

Active brute-force closes the gap. It generates candidate names from a wordlist (or several) and asks a DNS resolver whether they exist. A successful resolution is proof that the name was provisioned. The technique scales: tens of millions of resolutions are inexpensive when distributed across resolvers, and the cost is sub-linear with respect to the candidate space.

Active brute-force is also adversarial-ready. It does not depend on the target organization having published anything. The only inputs are the apex domain and a wordlist. Modern tooling (`dnsx`, `puredns`, `massdns`) does this at hundreds of thousands of queries per second, with wildcard handling, recursive resolution, and trusted-resolver rotation built in.

The outputs become the seed for further work: every newly-discovered name feeds permutation generation, vhost fuzzing, port scanning, and content discovery. Brute-force is the lever that converts compute and bandwidth into attack surface.

## Wordlist Strategy

The candidate space matters more than the resolver speed. A 10× larger wordlist with proper org-tuning will beat a 10× faster resolver every time.

### Universal short list (first pass, ~100k entries)

The first pass uses a curated wordlist of common subdomain names that appear in nearly every organization. The goal is high-yield coverage in minutes, not exhaustive coverage in hours. Examples of well-known short lists:

- SecLists `subdomains-top1million-5000.txt` and `subdomains-top1million-110000.txt`
- Jhaddix `all.txt` (~100k entries, mixed sources)
- AssetNote `2m-subdomains.txt` truncated to top-100k
- ProjectDiscovery's `commonspeak2-subdomains.txt`

The first-pass list runs against the target apex (and against every previously-discovered subdomain, recursively). It establishes a baseline of "easily found" names.

### Long-tail exhaustive list (second pass, ~1M+ entries)

The second pass uses a much larger wordlist: AssetNote's full 2m, n0kovo's 9m subdomains, or a custom-merged superlist. The yield-per-name is lower, but the long-tail covers names that no short list does.

Run the long-tail pass against the apex AND against the highest-value names discovered in the first pass (e.g., `*.api.target.example`, `*.auth.target.example`). Cost grows quadratically with depth, so apply the long-tail pass selectively to high-yield branches.

### Org-tuned list (derived from initial hits)

Once the universal lists have produced their hits, examine the naming convention. Real examples (paraphrased):

- One org consistently uses `<region>-<service>-<env>` (e.g., `us-east-payments-prod`)
- Another uses `<service>-<team>-<color>` (e.g., `auth-platform-blue`)
- A third uses `<incrementing-number>` (`api1`, `api2`, …)

Generate a wordlist that follows the discovered pattern. Combine the discovered tokens (regions, services, envs, teams, colors, numbers) cross-product. A 50-token × 50-token × 10-token cross-product is 25k candidates, all of which fit the org's actual naming convention. Yield per name is much higher than a generic list.

### Source-derived list

Mine candidate names from artifacts the target has produced:

- JavaScript bundles (chain to `js_analysis`) — extract `https://?-?.target.example` matches
- robots.txt and sitemap.xml — sometimes reference internal hosts
- Public GitHub repositories (chain to `github_dorking`) — `target.example` mentions in code, configs, CI
- Public job listings — engineering postings often name internal tools by their hostname
- Subdomain takeover candidates — DNS records pointing at unclaimed cloud resources
- Cloud-provider metadata — when the org uses a cloud provider, derive likely host patterns from their templates
- crt.sh wildcard cert SAN entries — names that share a cert with known subdomains

Source-derived names are higher precision than wordlist names: they are evidence that the name has been used somewhere, which raises the prior of a successful resolution.

## Resolution Primitives

The fast resolver is the bottleneck, not the candidate generator. Use the right tool for the job.

### dnsx (recommended default)

ProjectDiscovery's `dnsx` is the modern async resolver. It handles wildcards, accepts a custom resolver list, supports A / AAAA / CNAME / TXT / NS / MX / SOA queries, and is fast. Typical invocation:

```
dnsx -d {target.example} -w {wordlist.txt} -r 8.8.8.8,1.1.1.1,9.9.9.9 -t 100 -wd {target.example} -silent -o {results.txt}
```

Flags worth knowing:

- `-wd` enables wildcard detection on the apex
- `-t 100` tunes parallelism (lower for friendly resolvers, higher when you control the resolver)
- `-resp` includes the resolved IP in output
- `-cname` includes CNAME chains (catches takeover candidates)
- `-rcode noerror` filters by response code

`dnsx` reads from stdin, so it composes:

```
cat {wordlist.txt} | sed 's/$/.{target.example}/' | dnsx -resp -silent
```

### puredns (wildcard-aware bruteforce)

`puredns` wraps `massdns` with a robust wildcard-handling layer. When the target has aggressive wildcards, `puredns` is the safe choice:

```
puredns bruteforce {wordlist.txt} {target.example} -r {resolvers.txt} --wildcard-tests 30 --wildcard-batch 1500 -w {results.txt}
```

`puredns` validates each hit by re-resolving with multiple resolvers and confirming the response is consistent and not the wildcard signature.

### massdns (high-throughput)

`massdns` is the underlying high-performance resolver. Use directly when you need raw speed and have a clean resolver list:

```
massdns -r {resolvers.txt} -t A -o S -w {results.txt} {candidates.txt}
```

`massdns` does not handle wildcards on its own — pair with `puredns` or post-process with a wildcard-detection script. `massdns` is the right choice when running a 50M-name brute that would take other tools hours.

### subfinder (passive + light brute)

`subfinder` is primarily passive but has a `-recursive` flag that performs limited brute-force using its own wordlist. Use as a quick sanity check between heavy brute passes:

```
subfinder -d {target.example} -all -recursive -silent -o {results.txt}
```

It is not a substitute for `dnsx` or `puredns` brute — but it surfaces names from passive sources that may seed an org-tuned wordlist.

### shuffledns (massdns wrapper, simple)

`shuffledns` wraps `massdns` with sane defaults for brute-force:

```
shuffledns -d {target.example} -w {wordlist.txt} -r {resolvers.txt} -massdns $(which massdns) -o {results.txt}
```

A reasonable default when `puredns` is not installed.

## Wildcard Handling

Wildcards are the single largest source of false positives in active brute-force. Detect aggressively, validate every hit.

### Detect a wildcard

For each candidate apex, send a probe with a guaranteed-bogus name:

```
{random12chars}.{apex}
```

If this resolves, the apex has a wildcard. Repeat with several random names — if the response IPs are stable across probes, the wildcard is simple. If the response IPs vary (round-robin DNS, geo-DNS), the wildcard is complex and validation is harder.

Record the wildcard signature: the set of IPs that wildcard responses resolve to, and the typical TTL. Any "hit" that resolves to a subset of those IPs with that TTL is suspect.

### Validate a candidate hit

A candidate name "resolves" — does it actually exist as a distinct host?

1. **DNS layer**: does it resolve to IPs outside the wildcard set? If yes, real. If it resolves to the wildcard IPs, suspect — proceed.
2. **HTTP layer**: send a request with `Host: {candidate}` to one of the wildcard IPs. Compare the response signature to a request with `Host: {bogus-name}.{apex}`. If they differ → real vhost. If they match → wildcard echo.
3. **Cert layer**: if the IP serves TLS, check the certificate's CN/SAN. Does it cover the candidate name explicitly, or only the wildcard? Explicit coverage is strong signal of provisioning.

`puredns` does step 1 automatically. For steps 2 and 3, chain to `recon_vhost_fuzzing`.

### Subtle wildcard variants

- **Per-label wildcards**: `*.api.{apex}` is wildcard but `*.{apex}` is not. Test wildcard at every depth.
- **Geo-DNS / round-robin**: the wildcard's IP set varies by client location. Use multiple resolvers from different regions to characterize.
- **Conditional wildcards**: some servers return wildcard answers only for specific record types (A but not AAAA, or CNAME but not A). Probe all relevant record types.
- **Negative-cache wildcards**: a server may return NOERROR for any query but with no answer records. Some tools treat NOERROR-with-no-answer as a hit; it is not.

## Resolver Hygiene

Bad resolvers produce bad data. Curate.

### Trusted resolver list

Public DNS resolvers that are reliable, fast, and widely trusted:

- Cloudflare: 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111
- Google: 8.8.8.8, 8.8.4.4, 2001:4860:4860::8888
- Quad9: 9.9.9.9, 149.112.112.112
- OpenDNS: 208.67.222.222, 208.67.220.220
- Yandex: 77.88.8.8, 77.88.8.1

Maintain a list of 20-30 trusted public resolvers and rotate. Avoid using a single resolver for an entire campaign — caching may bias results.

### Rate-limit yourself

Public resolvers will rate-limit aggressive scanning. Treat them as a shared resource. A reasonable default for `dnsx`: `-t 100` (100 concurrent), which corresponds to a few thousand QPS in practice. For `massdns`: `-s 1000` (1000 QPS) per resolver as a rough cap.

When in doubt, run your own resolver. Spin up `unbound` or `bind` on a host with sufficient bandwidth, point the brute tool at it, and burn no shared-public-resource goodwill.

### Rotate resolvers and detect cache poisoning

Cross-check a sample of hits against a different resolver. If two resolvers disagree about whether a name resolves, one of them has stale or poisoned data. Treat divergent results with suspicion. Re-resolve through `1.1.1.1` and `8.8.8.8` and require consensus before counting a hit as confirmed.

### Resolver list source

For high-throughput brute (massdns), use a curated list of public open resolvers. ProjectDiscovery and trickest publish lists on GitHub that are known-clean as of a given date. Re-validate the list periodically — open resolvers go offline.

## Methodology

The full active brute-force pipeline has six stages.

### Stage 1: Initial pass

Run `dnsx` (or equivalent) against the apex with the universal short wordlist. Detect wildcards on the apex. Record all hits.

### Stage 2: HTTP-probe validation

For every hit from stage 1, probe HTTP on the resolved IP. Use `httpx`:

```
cat {hits.txt} | httpx -silent -title -tech-detect -status-code -content-length -o {http_validated.txt}
```

A hit that does not respond on HTTP/HTTPS is still a real subdomain — it may host non-HTTP services (mail, SSH, SIP, etc.). Do not discard, just tag.

### Stage 3: Permutation expansion

For every confirmed hit from stage 2, generate permutations (chain to `recon_subdomain_permutations`). The output is a new wordlist of candidates that follow the org's discovered naming convention.

### Stage 4: Recursive brute

Run `dnsx` against the new permutation wordlist on the apex. Then run against high-value confirmed branches (`*.api.{apex}`, `*.auth.{apex}`, `*.internal.{apex}`).

### Stage 5: Long-tail brute

Run the long-tail wordlist (~1M+ entries) against the apex and against the highest-value branches. Yield is lower per-name; total yield is higher.

### Stage 6: Iterate

Stages 3-5 form a loop. Every new hit feeds permutation, which feeds new candidates, which produces new hits. Continue until a full pass produces zero new resolutions (or until the resolver budget is exhausted, whichever comes first).

## Pitfalls

Active brute-force has well-known failure modes.

### Wildcard noise dominates results

If the wildcard is not handled correctly, the result file will be 80%+ false positives. A symptom: the result file has tens of thousands of "hits" all resolving to the same handful of IPs. Always validate via `puredns` or post-filter against the wildcard signature.

### IDN / punycode names

International names are encoded as `xn--*` in DNS. Most wordlists do not include punycode entries, so any IDN subdomain is invisible to a brute-force pass. For organizations with international presence, augment the wordlist with punycode-encoded forms of common terms in the relevant language.

### Internationalized TLDs

Apex domains under TLDs like `.中国`, `.рф`, `.한국` have their own ecosystems. Standard wordlists are biased toward `.com`-style apex names and miss patterns common in non-Latin TLDs.

### Anycast / always-resolve IPs

Some IPs respond to every query with NOERROR — typically anycast misconfigurations or sinkholes. Detect by sending a guaranteed-bogus query: if it succeeds, the resolver is lying or the upstream is responding to everything. Discard that resolver.

### Resolver bias

A single resolver may have a stale cache or geo-DNS-influenced results. Rotate resolvers and require multi-resolver consensus before declaring a hit "real." `puredns` does this with `--wildcard-tests` — set a high value (30+) for high-confidence results.

### Slow DNS responses bias throughput

`dnsx` and `massdns` both have query-timeout defaults. If a resolver is slow but answering, the tool may report timeouts when in fact the name resolves. Tune `-t` (timeout) per resolver and re-run timed-out candidates with longer timeouts.

### CNAME chains are hits, not just A records

A CNAME response means the name exists, even if the chain ends at a non-resolving target. Track CNAME hits separately — they are subdomain takeover candidates when the chain ends at an unclaimed cloud resource.

### TLDs with restricted access

Some TLDs (e.g., `.gov`, `.mil`, `.edu`) require permission to scan, and aggressive DNS brute on them may trip alerting. Confirm program scope before brute-forcing on restricted TLDs. (Same applies to government-adjacent ccTLDs in many countries.)

### Splitting brute across many TLDs

If the org owns `target.example`, `target.example.uk`, `target.example.co`, `target.example.io`, run brute against each separately. Apex-level wildcards differ per TLD and aggregate result counts are misleading without per-apex breakdown.

## Output Format

For every probed candidate, record:

```
{
  "name": "{full.subdomain.target.example}",
  "ip": ["{ip1}", "{ip2}"],
  "cname_chain": ["{intermediate}", "{final}"],
  "record_types_present": ["A", "AAAA", "CNAME"],
  "resolver_consensus": {
    "1.1.1.1": ["{ip1}"],
    "8.8.8.8": ["{ip1}"],
    "9.9.9.9": []
  },
  "consensus_status": "CONFIRMED|DIVERGENT|WILDCARD|NXDOMAIN",
  "distinct_from_wildcard": true,
  "wildcard_signature_match": false,
  "http_status_if_probed": {status},
  "http_title_if_probed": "{title}",
  "http_tech_if_probed": ["{tech1}", "{tech2}"],
  "tls_cert_san": ["{san1}", "{san2}"],
  "time_to_resolve_ms": {ms},
  "discovered_via": "wordlist|permutation|recursive|source-derived",
  "wordlist_source": "{wordlist-path-or-name}",
  "candidate_depth": {1=label-on-apex, 2=label-on-label, ...}
}
```

Persist as JSON Lines for easy filtering, joining, and re-feed into permutation generators.

## Composes With

- `recon_passive_subdomain` — initial seed for org-tuned wordlist generation; passive results identify the apex's naming convention
- `recon_subdomain_permutations` — every brute hit feeds permutation generation; permutations feed back into the next brute pass
- `recon_vhost_fuzzing` — validate brute hits at the HTTP layer; differentiate real vhosts from wildcard echoes
- `recon_port_service_analysis` — confirmed subdomains get full port scans
- `recon_asn_network_mapping` — IPs from brute hits seed ASN walks for related infrastructure
- `recon_information_disclosure` — every confirmed name gets path/file fuzzing
- `js_analysis` — JS bundles on confirmed apps reveal additional internal hostnames
- `github_dorking` — public repos may mention more subdomains than the brute found

Active brute is the central recon node: every other recon technique either feeds it or consumes its output.

## Termination

Active brute-force terminates when **every wordlist has been run against every confirmed branch and the latest pass produces zero new resolutions**, not when a finding count threshold is reached.

Concretely:

- Run universal short wordlist against the apex
- Run universal short wordlist against every confirmed branch (depth >= 2 entries also get brute)
- Run long-tail wordlist against the apex and high-yield branches
- Generate org-tuned wordlist from confirmed hits and run against the apex and confirmed branches
- Run source-derived wordlist (from JS, GitHub, robots.txt, archive sources)
- Re-run permutation-generated wordlist against the apex and confirmed branches
- Repeat the permutation→brute loop until a full iteration produces zero new resolutions

There is no "we have N subdomains, that's enough." Every additional resolution is one more piece of attack surface. The cost of one more candidate is one DNS query — single-digit microseconds of wall time on a fast resolver. The cost of a missed subdomain is the entire finding it would have led to.

When a full pipeline iteration produces zero net-new hits across every wordlist and every branch, the loop is done. Until then, continue.
