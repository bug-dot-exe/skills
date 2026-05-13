# Transport Security — Next.js / TypeScript Patterns

## HTTPS on Vercel

Vercel enforces HTTPS automatically for all deployments — no server-level
redirect needed. Add HSTS to ensure browsers never attempt plain HTTP:

```javascript
// next.config.js
const securityHeaders = [
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=31536000; includeSubDomains',
  },
]

module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }]
  },
}
```

## NODE_TLS_REJECT_UNAUTHORIZED

```bash
# DANGEROUS — disables certificate verification for ALL outbound requests
NODE_TLS_REJECT_UNAUTHORIZED=0
```

Search `.env` files, Dockerfiles, and CI configs for this variable. It is
sometimes set to work around a self-signed cert in staging and then copied
to production configs.

For legitimate self-signed cert needs, pass a custom CA bundle instead:

```javascript
const https = require('https')
const fs = require('fs')

const agent = new https.Agent({
  ca: fs.readFileSync('/path/to/ca-cert.pem'),
})
fetch(url, { agent })
```
