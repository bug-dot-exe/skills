---
name: mobile-api
category: archetypes
description: Mobile API testing covering certificate pinning bypass, API key extraction, token storage analysis, deep link hijacking, intent injection, biometric bypass, and local storage secrets
---

# Mobile API Testing

Security testing playbook for mobile applications and their backend APIs. Focus on certificate pinning bypass, API key extraction from APK/IPA, token storage analysis, deep link hijacking, intent injection, biometric bypass, and local storage secrets.

## When to Use

- Target has a mobile application (Android APK or iOS IPA)
- Mobile app communicates with a backend API
- Application uses biometric authentication or device binding
- Deep links or universal links handle authentication or sensitive actions
- Mobile app stores tokens, keys, or sensitive data locally

## Priority Checklist

### 1. Certificate Pinning Bypass

- **Frida-based bypass**: hook SSL/TLS validation functions to accept any certificate
- **Proxy certificate injection**: install custom CA on rooted/jailbroken device
- **Network security config (Android)**: check for debug-overrides allowing user CAs in production builds
- **OkHttp/AFNetworking hooks**: target specific HTTP library pinning implementations
- **Certificate rotation gap**: app rejects new legitimate certificates during rotation periods
- Test: run `frida -U -l ssl_bypass.js -f com.target.app` and proxy traffic through Burp Suite

### 2. API Key Extraction from APK/IPA

- **String search in binary**: decompile and grep for API keys, secrets, and hardcoded credentials
- **Resource files**: check AndroidManifest.xml, strings.xml, Info.plist, and embedded config files
- **Firebase/GCP key exposure**: google-services.json or GoogleService-Info.plist with unrestricted API keys
- **Build config leaks**: debug/staging endpoints and keys left in production builds
- **Native library secrets**: keys in .so/.dylib files; use `strings` or decompile with Ghidra
- Test: `apktool d app.apk && grep -rni "api_key\|secret\|token\|password" ./app/`

### 3. Token Storage Analysis

- **Insecure storage (Android)**: tokens in SharedPreferences (world-readable on rooted devices) instead of EncryptedSharedPreferences or Keystore
- **Insecure storage (iOS)**: tokens in UserDefaults or plist instead of Keychain with appropriate protection class
- **Token in logs**: authentication tokens written to system logs (logcat/Console)
- **Backup inclusion**: sensitive data included in device backups (android:allowBackup="true")
- **Clipboard exposure**: tokens or OTPs copied to clipboard accessible by other apps
- Test: authenticate, then inspect SharedPreferences/Keychain/sqlite databases for plaintext tokens

### 4. Deep Link Hijacking

- **Scheme hijacking (Android)**: custom URL scheme (myapp://) claimed by malicious app to intercept OAuth callbacks
- **Universal link misconfiguration (iOS)**: apple-app-site-association file missing or misconfigured
- **App link verification (Android)**: assetlinks.json absent, allowing unverified deep link handling
- **Sensitive action via deep link**: deep links trigger password reset, payment, or account linking without re-authentication
- **Parameter injection**: deep link parameters injected into WebView URLs or API calls without sanitization
- Test: register a test app handling the same scheme/domain; initiate OAuth flow and check which app receives the callback

### 5. Intent Injection (Android)

- **Exported component abuse**: activities, services, or receivers exported without permission checks
- **Intent redirection**: app receives an intent and forwards it to an internal component specified by attacker
- **PendingIntent hijack**: implicit PendingIntent intercepted by malicious app
- **Content provider exposure**: content providers without proper permission enforcement leak data
- **Fragment injection**: WebView-based activities accept attacker-supplied fragment names
- Test: `adb shell am start -n com.target.app/.InternalActivity -d "attacker://payload"`

### 6. Biometric Bypass

- **Fallback to PIN/password**: biometric prompt has a weak fallback that bypasses the biometric requirement
- **CryptoObject missing**: biometric authentication not bound to a cryptographic operation (result is just a boolean)
- **Frida hook on callback**: hook BiometricPrompt.AuthenticationCallback to force onAuthenticationSucceeded
- **Local-only validation**: biometric result checked client-side only, server receives same token regardless
- **Replay of biometric token**: capture the post-biometric auth token and replay without biometric interaction
- Test: hook the biometric callback with Frida to return success without actual biometric input

### 7. Local Storage Secrets

- **SQLite databases**: unencrypted databases containing user data, tokens, or transaction history
- **WebView cache/cookies**: sensitive data cached by embedded WebViews in app sandbox
- **File system artifacts**: temporary files, crash logs, or analytics files with sensitive content
- **Hardcoded secrets in code**: API keys, encryption keys, or credentials in decompiled source
- **Realm/Core Data inspection**: ORM databases with sensitive records accessible on rooted devices
- Test: pull app data from device (`adb backup` or filesystem access) and search for sensitive content

### 8. WebView JavaScript Bridge Exploitation

- **`@JavascriptInterface` method enumeration**: decompile the APK, find every class registered with `addJavascriptInterface`, and list all public methods; each method is callable from any page loaded in that WebView
- **Bridge method abuse via deep link**: if a deep link loads an attacker-controlled URL in a WebView with a JS bridge, the attacker page can call every bridge method (file read, token access, native API calls)
- **`postMessage` bridge to native**: some apps use `window.webkit.messageHandlers` (iOS) or custom `postMessage` bridges; inject messages from a malicious iframe loaded in the WebView
- **File scheme access**: if the WebView allows `file://` URLs, an attacker page loaded in the WebView can read local files via `XMLHttpRequest` to `file:///data/data/com.target.app/...`
- Test: find all `addJavascriptInterface` / `WKScriptMessageHandler` registrations, load your own HTML page in the WebView (via deep link or redirect), call every exposed method

### 9. System App as Confused Deputy

- **Privileged intent forwarding**: system apps (Settings, Camera, Contacts) often accept intents and forward them to internal components; send a crafted intent to the system app that it relays to a target component the attacker cannot reach directly
- **Content provider via system app**: a privileged system app may read from a content provider that is not exported to third-party apps; trigger the system app to read and relay the data
- **PendingIntent from system notification**: system-generated notifications with implicit PendingIntents can be intercepted by a malicious app matching the intent filter
- Test: list all intent filters of system apps with `adb shell dumpsys package | grep -A5 "systemApp"`, then craft intents that leverage the system app's elevated permissions

### 10. Multi-Client API Authorization Divergence

- **Web vs mobile permission gap**: the same API endpoint accepts requests from both web and mobile clients; test if the mobile client has broader access (e.g., admin endpoints accessible from mobile but not web)
- **Legacy API version exposure**: the mobile app hardcodes an older API version (`/v1/`) that has looser authorization than the current web version (`/v3/`)
- **Internal SDK endpoints**: mobile SDKs (analytics, crash reporting, push notification) expose endpoints that are not behind the same auth layer as the main API
- **Partner/developer API leakage**: the APK contains references to internal partner APIs or developer tools with different auth requirements
- Test: decompile the APK, extract every API endpoint URL, and test each one with the web session token and with no auth; compare accessible endpoints across clients

### 11. Deep Link CSRF

- **State-changing deep links without confirmation**: deep links that trigger actions (add friend, approve request, change setting) without showing a confirmation dialog
- **OAuth callback hijack via custom scheme**: register an app with the same custom URL scheme as the target; when the OAuth callback arrives, both apps compete to receive it
- **Universal link fallback to browser**: when the app is not installed, universal links fall back to the browser, potentially leaking auth tokens to the web context
- **Chained deep link to WebView**: a deep link loads a URL in an in-app WebView; if the URL is attacker-controlled, this chains to WebView JS bridge exploitation (see section 8)
- Test: enumerate every custom URL scheme and universal link from the manifest/Info.plist; for each, craft an HTML page with `<a href="targetapp://action?param=evil">` and test from a browser

### 12. S3 and Cloud Storage Misconfigurations

- **Upload destination takeover**: capture the upload URL from the app; test if the S3 bucket allows unauthenticated list, read, or write operations
- **Pre-signed URL parameter manipulation**: modify the `Content-Type`, `key` (path), or `acl` parameters in a pre-signed upload URL to write to a different path or make the file public
- **Download URL enumeration**: if download URLs use sequential or predictable keys, enumerate to access other users' uploaded files
- **Bucket name in APK**: hardcoded S3 bucket names in the APK/IPA; test the bucket for public access, directory listing, and credential-less write
- Test: capture every cloud storage URL from the app's network traffic, test each for public access (`curl -s https://bucket.s3.amazonaws.com/ | head`), and attempt to upload and list

### 13. Embedded Browser Engine Vulnerabilities

- **Bundled Chromium/WebKit version audit**: identify the exact browser engine version bundled in the app (check User-Agent, `chrome://version` in WebView, or binary strings); compare against CVE databases for known exploits
- **Cross-frame scripting (UXSS) in WebView**: test if a malicious page loaded in one WebView frame can access content in another frame via `window.parent`, `window.opener`, or shared JavaScript contexts
- **Extension/plugin processing in embedded engine**: if the app uses an embedded browser for document preview, test if it processes browser extensions, plugins, or protocol handlers
- Test: identify the embedded engine version via `navigator.userAgent` from within the WebView, then check if known exploits for that version (CVE lookup) apply in the app's sandboxing context

### 14. Cross-Feature State Persistence

- **Privacy setting bypass via alternate feature**: a user disables location sharing, but a different feature (photo EXIF, check-in, nearby-friends) still accesses and transmits location data
- **Deleted data persistence in cache**: user deletes a message or photo, but the content remains in WebView cache, SQLite FTS index, or thumbnail cache on disk
- **Account switching residual**: switch from account A to account B; check if account A's tokens, cached data, or push notification registrations persist and are accessible from account B's context
- Test: enable and disable every privacy-related setting, then inspect local storage, caches, and background network requests for data that should have been cleared

## Pro Tips

- **Mine the vendor's own bug taxonomy.** Google publishes `Android_app_vulnerability_classes.pdf`; Apple publishes secure coding guides. Use their own documented vulnerability classes as a checklist -- they wrote it because those bugs exist in their ecosystem.
- **Every exported component of a privileged app is an entry point.** Map all intent filters to callable WebViews and native functions. An exported activity in a system app with a WebView JS bridge is often a direct code execution path.
- **Mobile-deeplink CSRF is underreported and high-impact.** Deep links that trigger state-changing actions without user confirmation are the mobile equivalent of CSRF. Test every registered scheme.
- **Decompile first, proxy second.** Static analysis of the APK/IPA (endpoint URLs, API keys, exported components, JS bridges) should happen before you even set up the proxy. The decompiled code tells you what to look for in traffic.

## Validation

- Demonstrate pinning bypass with intercepted API traffic showing authenticated requests
- Show extracted API keys with proof of unauthorized API access using those keys
- Prove token theft from local storage with session hijacking or account access
- Confirm deep link hijacking with OAuth token interception by a malicious app
- Document device state, tools used, exact file paths, and observable security impact
