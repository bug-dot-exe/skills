---
name: aws-cloudfront
description: AWS CloudFront attack surface: behaviors misordering, signed URL abuse, origin S3 misconfig
depends_on: []
---

# Aws Cloudfront

CloudFront fronts S3, EC2, ALB. Common bugs: behavior path-pattern ordering allowing unauth access, signed URLs with replayable signatures, S3 origin allowing direct access bypassing CF.

## Common Bug Classes

- Behavior order: more specific path-pattern listed AFTER catch-all `*`
- Signed URL signatures replayable across resources or not time-bound
- S3 origin bucket public — bypass CloudFront entirely
- OAC/OAI not enforced — direct S3 URL fetch
- Cache poisoning via unkeyed headers between CloudFront and ALB/origin
- HTTP request smuggling at CloudFront-to-origin boundary
- Subdomain takeover on dangling CloudFront distribution CNAME records
- Web cache deception on authenticated endpoints

## Cache Poisoning Attacks (144 reports, $1.3M corpus)

### RFC-Violation Parser-Differential Poisoning
The highest-bounty pattern ($500K+ reports) in the corpus. Steps:
1. Identify the HTTP parsing chain: CloudFront -> ALB -> application server
2. Send bare carriage returns (`\r` without `\n`) in HTTP request lines and headers
3. Test how each layer parses ambiguous requests — CloudFront and the origin may disagree on where headers end and body begins
4. If CloudFront caches a response keyed to URL X but the origin processed it as URL Y, you can poison the cache
5. Test HTTP/2 to HTTP/1.1 downgrade at CloudFront — request-line injection via pseudo-headers (`:path`, `:authority`)

### Unkeyed Header Discovery
1. For each cached endpoint, fuzz headers one at a time while monitoring response changes
2. CloudFront-specific unkeyed vectors: `X-Forwarded-Host`, `X-Forwarded-Proto`, `Origin`, `Referer`
3. Use cache-buster query params (`?cb=<random>`) to isolate each test
4. If a header changes the response AND is not in the cache key (check `X-Cache`, `Age` headers), craft the poisoned entry
5. Cross-reference with the origin's framework — Rails, Django, Express each reflect different headers

### Web Cache Deception
1. Test authenticated endpoints with trailing path extensions: `/account.css`, `/dashboard/settings.js`
2. Check if CloudFront treats the request as cacheable based on the extension
3. Test path confusion: `/account/..%2fstatic/app.css` — CloudFront may cache by the normalized path while the origin serves `/account`
4. Verify with `X-Cache: Hit from cloudfront` header in subsequent unauthenticated requests

## HTTP Request Smuggling

### CL.TE / TE.CL Desync Matrix
Every CloudFront-to-origin pair should be probed with the four canonical desync patterns:
1. **CL.TE**: CloudFront uses `Content-Length`, origin uses `Transfer-Encoding`
2. **TE.CL**: CloudFront uses `Transfer-Encoding`, origin uses `Content-Length`
3. **TE.TE obfuscated**: Both support TE but with obfuscation (`Transfer-Encoding: chunked` vs `Transfer-Encoding: xchunked`)
4. **H2.CL desync**: HTTP/2 front-end -> HTTP/1.1 origin, inject via content-length mismatch

For each:
- Send a probe that smuggles a `GET /admin` request prefix
- Detect by observing the next request's response (reflected path, 404 on unexpected path)
- Use timing probes (pause-based desync) if standard probes are blocked

## S3 Origin Exploitation

### Direct S3 Access Bypass
1. Identify the S3 bucket from CloudFront responses (response headers, error pages, CORS headers)
2. Test direct access: `https://<bucket>.s3.amazonaws.com/<path>` and `https://s3.amazonaws.com/<bucket>/<path>`
3. If direct access works, all CloudFront-enforced auth (signed URLs, signed cookies) is bypassed
4. Test bucket listing: `/?list-type=2`, `/?delimiter=/`, `/?max-keys=1000`

### OAC/OAI Verification
1. If the origin has OAI (Origin Access Identity) or OAC (Origin Access Control), direct S3 access should fail
2. Test edge cases: `HEAD` instead of `GET`, different AWS regions, `?versionId=` parameter
3. Check if the bucket policy allows `s3:GetObject` with `Principal: *` alongside the OAI condition — the `*` may override

### Proxy-Elevated Bucket Listing
1. For CDN-fronted buckets, test listing via the CDN URL: `https://cdn.target.com/?list-type=2`
2. CloudFront may forward the listing query parameter to S3 even if the bucket denies direct listing
3. Test `?prefix=`, `?start-after=`, `?continuation-token=` for enumeration

## Subdomain Takeover

### Dangling CloudFront Distribution
1. Find CNAME records pointing to `*.cloudfront.net`
2. If the CloudFront distribution has been deleted, the CNAME dangles
3. Claim the distribution hostname by creating a new CloudFront distribution with the target domain as an alternate domain name (CNAME)
4. Also scan for CNAMEs pointing to decommissioned S3 buckets, ELBs, and Elastic Beanstalk environments

### Trust Inheritance
When a subdomain is taken over via CloudFront:
1. Check if the taken-over subdomain appears in any CSP `script-src`, `connect-src`, or `frame-ancestors` directive
2. Check CORS `Access-Control-Allow-Origin` headers for the parent domain
3. Check OAuth `redirect_uri` allowlists — a taken-over subdomain may be a valid redirect target

## ESI/SSI Injection

If the origin or CloudFront Lambda@Edge processes ESI/SSI tags:
1. Test for `<esi:include src="...">` injection on every reflected parameter
2. Check if Lambda@Edge functions process template tags in responses
3. If CloudFront Functions are used (lighter-weight than Lambda@Edge), test for injection in the function's response transformation logic

## CloudFront Signed URL/Cookie Exploitation

### Signature Replay and Scope Abuse
1. Capture a legitimate signed URL — analyze the signature scope (resource path, expiration, IP restriction)
2. Test if the signature works for sibling resources: if signed for `/files/a.pdf`, try `/files/b.pdf`
3. Check if the `Expires` parameter is validated server-side or only checked by CloudFront
4. Test if signed cookies are path-scoped or domain-wide — a cookie for `/premium/` may grant access to `/admin/`
5. If custom policies are used, test if the `Condition` block is properly restrictive

### Behavior Path-Pattern Ordering
CloudFront behavior rules are ordered — first match wins:
1. If the catch-all `*` behavior is listed before a restrictive behavior, the restriction never applies
2. Test: request a path that should be restricted (e.g., `/admin/`) — if it returns content without auth, behavior ordering is wrong
3. Check if new behaviors added after initial deployment were inserted in the wrong position
4. This is a configuration review, not a code bug — but the impact can be Critical (unauthenticated admin access)

## Lambda@Edge and CloudFront Functions

### Function Code Injection
1. If Lambda@Edge modifies response bodies or headers based on request input, test for injection
2. Lambda@Edge has four trigger points: viewer-request, origin-request, origin-response, viewer-response — test each
3. CloudFront Functions (lighter weight) have more restrictions but still may process user input unsafely
4. Test if the function writes CloudFront logs that include user input — log injection may be exploitable for log analysis tools

### Origin Request Manipulation
1. Lambda@Edge can rewrite the origin request — test if user input in headers/query affects the rewritten origin URL
2. If the function constructs an origin URL from user input, this is an SSRF vector
3. Test if the function's IAM role has excessive permissions (S3, DynamoDB, Secrets Manager access)

## Cross-Account and Cross-Region Issues

1. Test if CloudFront distributions in different AWS accounts share the same origin bucket
2. Check if signed URLs generated for one CloudFront distribution are valid for another distribution pointing to the same origin
3. Test cross-region failover behavior — does the failover origin have the same access controls as the primary?

## Probe Targets

- Identify S3 bucket from CloudFront origin (DNS / response headers)
- Test direct S3 access: `https://<bucket>.s3.amazonaws.com/<path>`
- Replay signed URL across slightly different paths
- Send conflicting CL/TE headers to probe for smuggling
- Test authenticated pages with `.css`/`.js`/`.jpg` extensions for cache deception
- Fuzz unkeyed headers on cached endpoints, monitor `X-Cache` for HIT
- Enumerate CNAME records to `*.cloudfront.net` for dangling distributions
- Test `?list-type=2` on CDN URLs for proxy-elevated bucket listing
- Check `X-Amz-Cf-Id` header for request tracing information leakage
- Probe Lambda@Edge/CloudFront Functions for ESI/template injection

## Cross-References

`aws`, `cloud_bucket_dorking`, `cache_poisoning`

## Validation Requirements

- Reproduce findings with at least one alternate principal where authz is involved
- Verify version disclosure aligns with the CVE list before claiming version-specific impact
- Distinguish "tech detected" from "tech vulnerable" — many fingerprints just identify the stack
