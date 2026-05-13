---
name: kubernetes_misconfiguration
category: vulnerabilities
description: Kubernetes misconfiguration testing for exposed dashboards, RBAC bypass, pod escape, service account abuse, and secret extraction
depends_on: []
---

# Kubernetes Misconfiguration

Exploiting Kubernetes cluster misconfigurations to achieve container escape, lateral movement, secret extraction, and cluster takeover. Kubernetes defaults are often insecure, and misconfigurations compound into full cluster compromise.

## Discovery Signals

| Signal | Where to Find | What It Means |
|--------|--------------|---------------|
| Port 6443/8443 open externally | Nmap, Shodan `port:6443 "kube"` | API server exposed to internet |
| Port 8080 open (insecure port) | Nmap, Shodan `port:8080 "api"` | Unauthenticated API server access |
| Port 2379/2380 open | Nmap, Shodan `port:2379 "etcd"` | etcd exposed — all secrets in plaintext |
| Port 10250 open (kubelet) | Nmap, `curl https://host:10250/pods` | Kubelet API — pod exec, log reading |
| `X-Kubernetes-` response headers | HTTP probing of discovered endpoints | Confirms Kubernetes API or dashboard |
| `kubernetes-dashboard` in subdomain/path | Subdomain enum, path brute | Dashboard potentially without auth |
| `runs-on: self-hosted` in public repos | GitHub workflow YAML grep | Self-hosted runner = K8s pod RCE surface |
| Cloud metadata reachable from pod | `curl 169.254.169.254` from container | IMDS access — cloud credential theft |
| `automountServiceAccountToken: true` (default) | Pod spec inspection | SA token available for API server auth |
| Ingress annotations with snippets | Ingress resource YAML | Config injection surface in ingress-nginx |
| `hostPID: true`, `privileged: true` in pod spec | `kubectl get pods -o yaml` | Container escape primitives |
| kOps/kubeadm state bucket accessible | GCS/S3 bucket from metadata service | CA private keys, bootstrap tokens → cluster admin |

## K8s Misconfiguration Matrix

| Component | Misconfiguration | Exploitation | Impact |
|-----------|-----------------|--------------|--------|
| API Server | Anonymous auth enabled (`--anonymous-auth=true`) | `kubectl --server=https://target:6443 get pods` without creds | Full cluster enumeration, potential write access |
| API Server | Insecure port 8080 exposed | Direct unauthenticated API access | Complete cluster control |
| etcd | Client port 2379 exposed without TLS client auth | `etcdctl get /registry/secrets --prefix` | All cluster secrets including SA tokens, TLS keys |
| Kubelet | Read-write port 10250 without auth | `/run` endpoint for arbitrary command execution in any pod | RCE in any container on the node |
| Dashboard | Skip-login enabled or no auth | Access via browser, create pods, view secrets | Cluster management without credentials |
| RBAC | Wildcard `*` on verbs/resources in ClusterRole | `kubectl auth can-i --list` reveals `*.*` permissions | Effective cluster-admin from any bound SA |
| RBAC | `system:authenticated` group has excessive bindings | Any valid token (including default SA) gets broad access | Privilege escalation from any pod |
| Service Account | Default SA automounted with cluster-wide roles | Read token from `/var/run/secrets/kubernetes.io/serviceaccount/token` | API access from compromised container |
| Pod Security | `privileged: true` container | `mount /dev/sda1 /mnt && chroot /mnt` | Full node filesystem access, container escape |
| Pod Security | `hostPID: true` | `nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash` | Host namespace access |
| Ingress-nginx | Annotation injection (config/server/auth snippet) | Inject nginx directives → `log_format` file write → `include` → Lua RCE | Cluster-wide secret theft ($2.5K x4 K8s bounties) |
| Cloud metadata | No NetworkPolicy blocking 169.254.169.254 | `curl -H "Metadata-Flavor: Google" metadata.google.internal/...` | Cloud IAM credentials from any pod |

## Container Escape Techniques

| Escape Vector | Prerequisite | Technique | Impact |
|---------------|-------------|-----------|--------|
| Privileged container | `privileged: true` in securityContext | `mount /dev/sda1 /mnt/host && chroot /mnt/host` | Full node control — R/W host filesystem |
| Host PID namespace | `hostPID: true` in pod spec | `nsenter --target 1 --mount --uts --ipc --net --pid -- bash` | Host process namespace, full node access |
| Docker socket mount | `/var/run/docker.sock` hostPath volume | `docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt` | Node control via container runtime |
| Host path mount | `hostPath` volume to `/`, `/etc`, `/var` | Direct read/write of host files; write cron job or SSH key | Persistent node access |
| CAP_SYS_ADMIN | `capabilities: [SYS_ADMIN]` without seccomp | `mount -t cgroup -o rdma cgroup /tmp/cgrp && echo 1 > /tmp/cgrp/notify_on_release` | cgroup escape to host RCE |
| Kernel exploit | Unpatched kernel + container shares kernel | CVE-2022-0185 (fsconfig), CVE-2022-0847 (Dirty Pipe) | Kernel-level escape to host |
| Service account token + create pods | SA with `pods: create` permission | Create privileged pod with host mount → escape via new pod | Escalate from API access to node access |

## Defense-Bypass Pairs

| Defense | Bypass | Corpus Evidence |
|---------|--------|----------------|
| PodSecurityPolicy/Admission (deny privileged) | Create pod with `hostPID: true` + `nsenter` (not caught by "privileged" check) | Alternate escape vector not in deny list |
| RBAC deny on `get secrets` | `create pods` permission → mount secrets as volumes in new pod | #1382919 — Ingress SA token with secrets:list |
| NetworkPolicy blocking metadata | Pod-to-pod lateral movement to a pod WITHOUT the NetworkPolicy, then curl metadata | Standard multi-hop bypass |
| Ingress annotation sanitizer | Use unsanitized sibling annotation (permanent-redirect, mirror-target) | #2039464 ($2.5K), #1728174 ($2.5K) — annotation drift |
| Ingress annotation sanitizer (regex) | nginx variable substitution: `set $a "lua"; ${a}_code_block` | #1728174 — grammar polymorphism bypass |
| SameSite=Lax on Argo CD | Attacker controls subdomain on same eTLD+1 → same-site CSRF | #2326194 ($4.7K) — CSRF → cluster compromise |
| IMDSv2 (AWS token-based metadata) | Many pods have `IMDSv2` hop limit=1 but containers on the same node have hop limit=2 | Instance metadata hop limit misconfiguration |
| Admission webhook denying `hostPath` | Use CSI driver volume or `emptyDir` with `medium: Memory` and mount sensitive paths | Alternate volume types bypass hostPath check |
| kOps bucket encryption | Bucket access is the bypass — encryption at rest doesn't prevent authorized reads | #1842829 ($2.5K) — node SA reads entire state bucket |

## Chain Patterns

| Chain | Steps | Evidence |
|-------|-------|---------|
| Ingress annotation → cluster admin | Namespace user creates Ingress with snippet annotation → nginx config injection → `log_format` file write → `include` Lua RCE → steal ingress-nginx SA token → `secrets:list` cluster-wide | #1620702, #1728174, #2039464 ($2.5K each) |
| Pod shell → cloud account | Shell in any pod → `curl 169.254.169.254` → steal cloud IAM creds → `aws sts get-caller-identity` → full cloud access | #776017 ($5K) — CCM SSRF → cloud creds |
| kOps state bucket → cluster admin | Pod shell → metadata service → node SA token → `gsutil cat gs://state-bucket/cluster.spec` → CA private key → mint `system:masters` cert | #1842829 ($2.5K) — kOps GCP PE |
| Windows node → command injection | PVC with crafted path → kubelet shells out to `cmd.exe` → unsanitized path = command injection | #2231019 ($5K) — CVE-2023-5528 |
| CSRF on GitOps tool → cluster compromise | Stored XSS on subdomain → CSRF Argo CD Application create → malicious repo manifest deployed → reverse shell with cluster-admin SA | #2326194 ($4.7K) — Argo CD CSRF |
| Ingress create → 4+ sequential CVEs | Same architectural flaw (annotation→config injection) exploited via different annotations across 4 CVE cycles | Pattern: annotation-sanitizer drift |
| Service mesh sidecar → privilege escalation | Envoy sidecar misconfiguration → intercept/modify traffic between pods → extract auth tokens from inter-service calls | Istio/Envoy lateral movement pattern |
| Helm chart → persistent backdoor | Malicious Helm chart in shared repo → includes ClusterRoleBinding to attacker SA → survives namespace deletion | Helm supply chain attack |
| Kubelet API → node takeover | Exposed kubelet 10250 → `/run` endpoint executes commands in any pod → escalate to host via privileged pod | Kubelet API exploitation chain |

## Methodology

### Step 1: External Enumeration
- Discover API server, dashboard, etcd, kubelet endpoints via subdomain enum and port scanning
- Shodan: `port:6443 "kube"`, `port:10250`, `port:2379 "etcd"`, `"kubernetes-dashboard"`
- Check for unauthenticated endpoints: `/api`, `/apis`, `/healthz`, `/version`

### Step 2: Authentication Testing
- Anonymous auth: `kubectl --server=https://target:6443 get namespaces`
- Dashboard: `https://target/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/`
- Kubelet: `curl -sk https://target:10250/pods`
- etcd: `etcdctl --endpoints=https://target:2379 get / --prefix --keys-only`

### Step 3: RBAC Mapping (from pod shell)
```bash
kubectl auth can-i --list
kubectl auth can-i create pods
kubectl auth can-i get secrets --all-namespaces
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
```

### Step 4: Pod Security Assessment
```bash
# Check if privileged
cat /proc/1/status | grep CapEff
# 0000003fffffffff = privileged container
# Check host mounts
mount | grep -E '/dev/(sd|nvme|xvd)'
ls -la /var/run/docker.sock 2>/dev/null
# Check host PID
ps aux | grep -c kubelet  # >0 means hostPID
```

### Step 5: Cloud Metadata Probing
```bash
# AWS
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# GCP
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Azure
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

### Step 6: Ingress Controller Audit
- Enumerate all annotations the controller accepts from source/docs
- Cross-reference against CVE patches to find unsanitized annotations
- Create test Ingress with snippet annotations, inspect rendered `nginx.conf`
- Check ingress-nginx SA permissions: `kubectl auth can-i --list --as=system:serviceaccount:ingress-nginx:ingress-nginx`

### Step 7: Escape and Lateral Movement
- If privileged: mount host filesystem, chroot
- If hostPID: nsenter to host namespace
- If docker.sock: spawn privileged container on host
- Use extracted credentials for lateral movement to other services

## Validation

- Dashboard access: screenshot showing unauthorized access to cluster resources
- RBAC escalation: demonstrate permission escalation from limited to admin
- Pod escape: prove host-level access from inside a container
- Secret extraction: show extracted secret values (sanitized in report)
- Metadata access: demonstrate cloud credential retrieval from pod
- Ingress injection: show injected nginx config and resulting RCE

## False Positives

- API server returns 401/403 on all requests (auth working correctly)
- Dashboard behind VPN/auth proxy with no skip-login
- Service account token present but has no permissions (`kubectl auth can-i --list` returns empty)
- `hostPath` mount is read-only and scoped to a non-sensitive directory
- Metadata service blocked by NetworkPolicy (verify from the actual pod, not assumptions)
- Ingress annotations sanitized by current controller version with no bypass

## Pro Tips

1. Ingress-nginx annotation injection is the gift that keeps giving — 4+ CVEs from the same architectural flaw. When a patch covers one annotation, check every sibling annotation the controller accepts
2. The "sanitizer/handler list drift" pattern: controller maintains "annotations we accept" and "annotations we sanitize" as separate lists. The delta is the attack surface
3. Cloud-bootstrap state buckets (kOps, kubeadm, Cluster API) are universal escalation primitives — node SA reads the bucket, bucket contains CA private keys
4. Windows Kubernetes nodes are under-audited — shell-out paths through `cmd.exe`/PowerShell are fertile ground for command injection
5. For ingress injection, the two-stage chain is: find a file-write primitive (`log_format` + `access_log`) then a file-include primitive (`include`) — sanitizers focus on direct exec, not indirect chains
6. Argo CD CSRF is exploitable from any subdomain on the same eTLD+1 — SameSite=Lax is site-level, not origin-level protection
7. Every infrastructure controller (ingress, sidecar, webhook, operator) that templates user input into a DSL config is a potential injection target
8. Patch-diff-driven hunting on ingress-nginx: read the CVE patch, find the regex, ask "what character class or alternative syntax did they miss?"
9. Pod-to-metadata-service is the highest-ROI check from any container shell — cloud creds are usually one curl away
10. When reporting K8s bugs, frame impact as "namespace-scoped RBAC user → cluster admin" — that trust boundary violation is what makes it Critical

## Summary

Kubernetes misconfigurations compound into full cluster compromise. The highest-yield patterns are: ingress-nginx annotation injection (same architectural flaw across 4+ CVEs), cloud metadata access from pods (one curl to cloud account takeover), and RBAC escalation via `create pods` or SA token theft. From outside, enumerate exposed API servers, dashboards, etcd, and kubelet. From inside a pod, check privileges, metadata access, and SA permissions. Ingress controllers that template user annotations into config files are systematic injection targets — audit every annotation against every CVE patch.
