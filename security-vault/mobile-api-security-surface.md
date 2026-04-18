# Mobile API Security — Deep Links & Pinning

**Tags:** #high #mobile #api #deeplink #certificate-pinning #android #ios
**OWASP:** MASAS-L1: Improper Communication Security / MASAS-L2: Improper Platform Usage
**CVSS Base:** 6.5 (Medium) — 8.1 (High if leading to account takeover)

---

## 📖 What it is

Mobile applications consume APIs in a different way than web browsers. They use custom URI schemes (Deep Links) and are often trusted more by the server. Security failures occur when Deep Links allow data theft or when the lack of Certificate Pinning allows trivial interception.

---

## 🔍 `grep_search` Tactics

```
intent://
custom_scheme
DeepLink
Uri.parse
checkServerTrusted
X509TrustManager
allowsUntrustedCertificate
onReceivedSslError
NSAppTransportSecurity
```

---

## 💣 Attack Category 1: Deep Link Intent Hijacking

Deep links allow apps to handle specific URLs. If an app uses a deep link to receive sensitive data (like an OAuth code) without proper validation, an attacker can register an app with the same scheme and steal the data.

**Vulnerable Patterns:**
- **Android Manifest:** `<intent-filter>` with a custom `android:scheme` that is too generic.
- **Node.js/Express API:** Sending an OAuth redirect to `com.myapp://callback?code=...`.

**Static Detection:** Search for custom URI schemes in the API configuration or documentation. Trace how the API handles "Callback URLs" for mobile clients.

### [NEW] URL Scheme Collision
**How it works:** Multiple apps can register for the same custom scheme (e.g., `myapp://`). The OS may prompt the user or pick one. An attacker app can intercept the callback.
**Mitigation:** Use Android App Links or iOS Universal Links (verified via `.well-known/assetlinks.json`).

### [NEW] In-App Browser (WebView) Token Theft
**How it works:** If a mobile app opens an In-App Browser to a page with XSS, the attacker can use `window.JSInterface` (if improperly exposed) to steal tokens from the native app memory.

---

## 💣 Attack Category 2: Lack of Certificate Pinning

By default, apps trust any CA in the user's system. An attacker with a malicious CA installed can intercept all API traffic.

**Vulnerable Logic (Android/Java):**
```java
// VULNERABLE - trusts all certificates
@Override
public void checkServerTrusted(X509Certificate[] chain, String authType) {
    // Empty implementation = trust all
}
```

**Secure Implementation:** Use `Network Security Configuration` (Android) or `SSLPinnedLinker`.

---

## 💣 Attack Category 3: Mobile-Only Endpoints

Developers often create separate endpoints for mobile (`/api/mobile/v1/...`) that might have less rigorous security checks than the web version.

**Tactic:** Scan for `/mobile`, `/app`, `/v1/mobile` prefixes. Check if these endpoints share the same middleware for authentication and rate limiting.

---

## 🧪 Validation Script (Deep Link Spoofing)

Since we cannot run a mobile emulator, we validate the **server-side** configuration:

```python
# .tmp/test_mobile_callback.py
import requests

# Test if the API allows registration of generic OAuth callbacks
TARGET = "http://api.myapp.com/auth/register-callback"
PAYLOAD = {
    "client_id": "mobile-app",
    "redirect_uri": "any-scheme://stolen-code" # Should be blocked if not whitelisted
}

r = requests.post(TARGET, json=PAYLOAD)
if "any-scheme" in r.text or r.status_code == 200:
    print("[HIGH] API allows arbitrary deep-link callback registration!")
```

---

## 🛡️ Fix

1. **App Links / Universal Links:** Use verified app links (`https`) instead of custom schemes (`com.myapp://`).
2. **Strict Whitelisting:** The server must only redirect to pre-registered, strictly validated mobile callbacks.
3. **Certificate Pinning:** Implement public key pinning for all production API connections.
4. **Unified Middleware:** Ensure mobile and web endpoints share the same security backbone.

---

## 🔗 Chain Exploits

```
Deep Link Hijacking + OAuth Callback  Full Account Takeover
Lack of Pinning + Public Wi-Fi  Credential theft via MitM
Mobile Endpoint Bypassing Web-Only Rate Limit  Admin brute force
```

---

## 📌 References
- [OWASP Mobile Security Testing Guide](https://mobile-security.gitbook.io/mobile-security-testing-guide/)
- [Android Deep Link Security](https://developer.android.com/training/app-links/deep-linking)
- [[cert-pinning-protocol]]
