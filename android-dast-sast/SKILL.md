---
name: android-dast-sast
category: mobile
description: Android dynamic and static testing covering APK analysis, ADB data extraction, exported components, certificate pinning bypass, and intent interception
depends_on: []
---

# Android DAST/SAST

Dynamic and static security testing for Android applications. Focus on APK decompilation and analysis, ADB-based data extraction, exported component testing, certificate pinning bypass, and intent interception.

## When to Use

- Android APK is in scope for security testing
- Mobile application communicates with a target API
- Client-side security controls need validation (pinning, root detection, encryption)
- Sensitive data storage on device needs assessment
- Inter-process communication (IPC) attack surface needs testing

## Methodology

### 1. Static Analysis (SAST)

**APK Decompilation**
```bash
# Decompile APK to smali + resources
apktool d target.apk -o target_decompiled

# Extract Java source (for review, not recompilation)
jadx target.apk -d target_jadx

# Extract strings, URLs, API keys
strings target.apk | grep -iE "api[_-]?key|secret|token|password|https?://"
grep -rn "api_key\|secret\|token\|password" target_jadx/
```

**AndroidManifest.xml Analysis**
- Exported components: activities, services, receivers, providers with `exported="true"` or intent filters
- Permissions: custom permissions, dangerous permissions, permission protection levels
- Backup settings: `android:allowBackup="true"` exposes app data via `adb backup`
- Debuggable flag: `android:debuggable="true"` allows runtime attachment
- Network security config: check for cleartext traffic, custom trust anchors
- Deep links and URL schemes: custom schemes (myapp://), app links (https://)

**Code Review Targets**
- Hardcoded credentials, API keys, encryption keys in source/resources
- Insecure crypto: ECB mode, static IVs, hardcoded keys, weak algorithms (MD5, SHA1 for security)
- WebView: `setJavaScriptEnabled(true)` + `addJavascriptInterface()` + loading untrusted content
- SQL injection in ContentProviders (`rawQuery` with string concatenation)
- Path traversal in ContentProviders (`openFile` without path validation)
- Insecure random: `java.util.Random` instead of `SecureRandom`

### 2. Dynamic Analysis (DAST)

**ADB Data Extraction**
```bash
# List installed packages
adb shell pm list packages | grep {target}

# Extract APK from device
adb shell pm path {package}
adb pull {path_to_apk}

# Shared preferences (run-as or root required)
adb shell run-as {package} cat /data/data/{package}/shared_prefs/*.xml

# SQLite databases
adb shell run-as {package} ls /data/data/{package}/databases/
adb shell run-as {package} cat /data/data/{package}/databases/{db}
# Pull and inspect with sqlite3

# Application logs
adb logcat --pid=$(adb shell pidof {package}) | grep -iE "token|key|password|secret"

# Clipboard monitoring
adb shell service call clipboard 2 s16 com.android.shell

# Check for world-readable files
adb shell run-as {package} ls -la /data/data/{package}/
```

**Exported Component Testing**
```bash
# Launch exported activities
adb shell am start -n {package}/{activity}
adb shell am start -a {action} -d {data_uri}

# Send broadcasts to exported receivers
adb shell am broadcast -a {action} --es key value

# Query exported content providers
adb shell content query --uri content://{authority}/{path}
adb shell content read --uri content://{authority}/{path}/{id}

# Start exported services
adb shell am startservice -n {package}/{service}
```

**Intent Interception**
- Use Drozer or manual ADB to test implicit intents for data leakage
- Intercept and modify intents between activities (pending intent hijacking)
- Test deep link handlers with malformed URIs for injection or bypass
- Check for intent redirection: exported activity that starts another activity based on intent extras

### 3. Certificate Pinning Bypass

**Frida-based Bypass**
```bash
# Generic SSL pinning bypass
frida -U -l ssl_pinning_bypass.js -f {package}

# Using objection
objection -g {package} explore
# Then: android sslpinning disable
```

**Other Approaches**
- Network security config modification (recompile APK with custom config)
- Magisk + TrustUserCerts module (system-wide CA trust on rooted device)
- Patch specific pinning library calls (OkHttp CertificatePinner, TrustManager)

### 4. Runtime Instrumentation

**Frida Hooks**
```bash
# Attach to running app
frida -U {package}

# Hook specific methods
frida -U -l hook_script.js {package}

# Common targets:
# - Crypto operations (key generation, encrypt/decrypt)
# - Authentication functions (login, token validation)
# - Root/emulator detection methods
# - Biometric authentication callbacks
```

**Bypass Techniques**
- Root detection: hook common checks (su binary, Magisk, build tags, installed packages)
- Emulator detection: hook Build.FINGERPRINT, HARDWARE, PRODUCT checks
- Tamper detection: hook signature verification, APK hash checks
- Biometric bypass: hook BiometricPrompt.AuthenticationCallback

## Key Commands

```bash
# APK tools
apktool d target.apk                    # Decompile
apktool b target_decompiled -o mod.apk  # Recompile
jadx target.apk -d output               # Java source
keytool -printcert -jarfile target.apk   # Signing cert info

# ADB essentials
adb devices                              # List connected devices
adb shell dumpsys package {pkg}          # Full package info
adb shell pm list permissions -g         # All permissions
adb install -r modified.apk             # Install modified APK

# Network
adb reverse tcp:8080 tcp:8080           # Proxy setup
adb shell settings put global http_proxy host:port

# Frida
frida-ps -Ua                            # List running apps
objection -g {package} explore          # Objection shell
```

## Corpus-Derived Attack Patterns

### WebView JS Bridge to Sandbox Escape
For every mobile app that exposes a WebView with a JS bridge: decompile and find `@JavascriptInterface` / `addJavascriptInterface` / `postMessage` / `evaluateJavascript` calls. Map every method exposed to JavaScript. Then find any path to load attacker-controlled content in that WebView (XSS on a trusted domain, deep link to attacker URL, MITM on HTTP loads). JS bridge methods in privileged app contexts can read contacts, files, tokens, or execute system-level actions.

### Exported Component Sink Data Flow Analysis
For every exported `<activity>`, `<service>`, `<receiver>`, `<provider>` in the manifest: trace the data flow from the exported entry point to sensitive sinks (file operations, database queries, intent forwarding, WebView loads, network requests). Focus on intent extras and URI parameters that reach sinks without validation. Path traversal via `../` in content provider URIs and intent redirection via unvalidated `getParcelableExtra("intent")` are the highest-value patterns.

### System App Confused Deputy via Intent
Privileged system apps (GMS, Settings, Photos, Telephony) frequently send intents that originate from a high-privilege context but carry user-supplied data. A third-party app can craft an intent that triggers a system app to perform a privileged action (file access, settings change, account modification) on the attacker's behalf. Audit every cross-app intent handler in privileged system apps for confused deputy scenarios.

### Patch-Bypass Hunting on Mature Platforms
When a security issue is fixed in an Android app: read the patch carefully, identify the exact validation added, and test whether the validation can be bypassed via encoding, alternative parameters, or different code paths that lead to the same sink. Patch-bypass hunting has one of the highest ROI rates on mature platforms because the original bug confirms the sink is reachable.

### Intent Redirection via Exported Activity
Test every exported activity for intent redirection: activities that read an Intent from extras (`getParcelableExtra("intent")` or `getIntent().getData()`) and use it to start another activity or service. If the inner intent is not validated, an attacker can redirect the exported activity to start any component (including non-exported ones) within the target app's context.

### Deep Link Handler Injection and Bypass
For every registered deep link and app link: test with malformed URIs (extra path segments, encoded characters, fragment injection, authority confusion). Deep link handlers that parse URI parameters into file paths, database queries, or WebView URLs are injection targets. Also test whether deep links bypass authentication screens that would normally gate the target activity.

### Cross-Feature State-Persistence Regression
For any privacy/security setting in the app: enumerate every other feature and test whether using that feature resets, disables, or overrides the security setting. Example: changing email address may unset "protect your posts" or disable 2FA. This is a state-persistence regression that occurs when feature code paths do not preserve cross-cutting security state.

### Mobile Deeplink CSRF Audit
For every registered custom URL scheme and app link: (1) enumerate all intent-filter schemes from the manifest, (2) for each scheme, craft a URL that triggers a state-changing action (follow, delete, purchase, authorize), (3) test whether the action executes without user confirmation when the link is opened from a browser, email, or another app. Custom URL scheme handlers rarely implement CSRF protection.

### Firebase/Cloud API Key Misuse
Audit every API key embedded in the APK (Firebase, GCP, AWS, Azure). Test whether the key is used only for identification (acceptable) or also for authorization (vulnerability). Firebase API keys with overly broad permissions can allow unauthorized database writes, storage access, or dynamic link creation on behalf of the target application.

### Regional/Legacy Domain Enumeration
For mature programs with hardened main stacks: enumerate regional and legacy domains (China, India, Japan variants; legacy acquisitions; internal tools). These secondary domains often run older code, have weaker CSRF protection, and may share session cookies with the main domain. Test every feature on secondary domains for bugs that are fixed on the primary domain.

## Validation

- Demonstrate sensitive data extracted from device storage (credentials, tokens, PII)
- Show exported component abuse leading to unauthorized actions or data access
- Prove certificate pinning bypass enables traffic interception
- Confirm intent interception or redirection with attacker-controlled data
- Document exact ADB/Frida commands, device state, and observed results
