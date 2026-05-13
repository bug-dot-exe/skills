# Configuration / Deployment Issues

**Preferred format:** Minimal config + demonstration command

```yaml
# docker-compose.yml exposes debug port to all interfaces
services:
  app:
    ports:
      - "0.0.0.0:9229:9229"  # Node.js debug port — accessible externally
```

```bash
# Connect to exposed debug port from external machine
node inspect TARGET:9229
# Result: full code execution in application context
```
