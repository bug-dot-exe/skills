# Cryptographic Vulnerabilities

**Preferred format:** Script demonstrating the mathematical/logical weakness

Focus on showing *why* the cryptographic construction fails:

- **Weak randomness:** Generate multiple tokens/keys, show predictable pattern
- **ECB mode:** Encrypt structured data, show block patterns
- **Padding oracle:** Script performing the oracle queries with timing/response analysis
- **Hash collisions:** Provide two distinct inputs producing the same hash
- **Hardcoded secrets:** Show the secret and demonstrate forgery

Always explain the cryptographic principle being violated.
