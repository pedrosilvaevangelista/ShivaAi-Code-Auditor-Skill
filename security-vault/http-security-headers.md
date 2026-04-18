# HTTP Security Headers

**Tags:** #medium #headers #csp #hsts #browser-security
**OWASP:** A05:2021 Security Misconfiguration
**CVSS Base:** 0.0 (Info isolated) → amplifier for other vulnerabilities

---

## 📖 What is it

HTTP Security Headers are not vulnerabilities in themselves, but **impact amplifiers** — their absence makes other vulnerabilities (XSS, Clickjacking, MitM) significantly more severe. Reclassify adjacent findings when critical headers are missing.

---

## 🔍 `grep_search` Tactics

```
helmet(
helmet.contentSecurityPolicy
app.use(helmet
res.setHeader
add_header
Content-Security-Policy
Strict-Transport-Security
X-Frame-Options
X-Content-Type-Options
Referrer-Policy
Permissions-Policy
```

---

## 📊 Required Headers Matrix

| Header | Recommended Value | Absence Allows |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'` + whitelist | Unrestricted XSS, external script injection |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | HTTP downgrade, MitM |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Clickjacking, UI redressing, iframe embedding |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing → XSS via file upload |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Sensitive tokens/paths leaked in Referer |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Unauthorized access to user hardware |
| `Cache-Control` | `no-store` (on private routes) | Sensitive data cached in the browser |
| `Cross-Origin-Opener-Policy` | `same-origin` | Side-channel attacks (Spectre) |
| `Cross-Origin-Resource-Policy` | `same-origin` | Cross-origin data leaks |

---

## 🔑 Content-Security-Policy (CSP) — Deep Dive

### Essential Directives

```
default-src 'self'           Only resources from the same domain
script-src 'self'            Scripts from the same domain only
script-src 'nonce-{NONCE}'   Only scripts with a dynamic nonce
object-src 'none'            Block Flash/plugins
base-uri 'self'              Prevent <base> injection
frame-ancestors 'none'       Block embedding in iframes (= X-Frame-Options: DENY)
upgrade-insecure-requests    Force HTTPS on embedded resources
```

### Examples by Environment

```
# Strict mode (preferred)
Content-Security-Policy: default-src 'none'; script-src 'self' 'nonce-{RANDOM}'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self';

# Moderate mode (practical)
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self';

# Report-only mode (does not block, only reports)
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-violations
```

### Poorly Configured CSP Bypasses

```
# Excessive wildcard
Content-Security-Policy: script-src *    → useless

# unsafe-inline (negates XSS protection)
Content-Security-Policy: script-src 'self' 'unsafe-inline'

# unsafe-eval (allows eval())
Content-Security-Policy: script-src 'self' 'unsafe-eval'

# Allow-list with insecure CDN
Content-Security-Policy: script-src 'self' cdn.example.com
# If cdn.example.com has a JSONP endpoint → bypass via JSONP
```

---

## 🔑 HSTS — HTTP Strict Transport Security

```
# Minimum secure
Strict-Transport-Security: max-age=31536000

# Maximum secure (with subdomains and preload)
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Without HSTS:**
- First visit can be intercepted (if the user types `http://...`)
- SSL stripping attack: attacker removes HTTPS from all responses
- Downgrade MitM: full session in cleartext

---

## 🔑 X-Frame-Options

```
X-Frame-Options: DENY                → can never be embedded (preferred)
X-Frame-Options: SAMEORIGIN          → only iframes from the same domain
X-Frame-Options: ALLOW-FROM https://trusted.com   → deprecated
```

**Without X-Frame-Options:**
- Clickjacking: attacker embeds your app in an invisible iframe and captures the user's clicks
- UI Redressing: capturing credentials via overlaid inputs
- Drag-and-drop data exfiltration

---

## ⚙️ Implementation by Framework

### Express.js — Helmet

```javascript
//  CORRECT — Helmet with explicit configuration
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));
```

### Django

```python
# settings.py —  CORRECT
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
X_FRAME_OPTIONS = 'DENY'
SECURE_SSL_REDIRECT = True

CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_OBJECT_SRC = ("'none'",)
CSP_FRAME_ANCESTORS = ("'none'",)
```

### Flask

```python
from flask_talisman import Talisman

Talisman(app,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'object-src': "'none'",
    },
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    x_frame_options='DENY',
    referrer_policy='strict-origin-when-cross-origin'
)
```

### NGINX

```nginx
#  CORRECT — nginx.conf
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';" always;
```

---

## 🔗 Chain Exploits (Reclassifications Due to Missing Headers)

```
Stored XSS 🟡 + No CSP → 🟠 High (arbitrary script with no restriction)
Reflected XSS 🔵 + No CSP → 🟡 Medium → 🟠 High
No HSTS → First access over HTTP → Credentials intercepted (MitM) → 🟠 High
No X-Frame-Options → Clickjacking on payment form → 🟠 High
MIME sniffing + SVG upload → XSS via misidentified Content-Type → 🟡 Medium
```

---

## 🛠️ Verification Tool

```python
# .tmp/check_headers.py
import requests

TARGET = "http://target.com"

REQUIRED_HEADERS = {
    "Content-Security-Policy": "🔴 Protects against XSS",
    "Strict-Transport-Security": "🟠 Protects against MitM/downgrade",
    "X-Frame-Options": "🟡 Protects against Clickjacking",
    "X-Content-Type-Options": "🟡 Protects against MIME sniffing",
    "Referrer-Policy": "🔵 Prevents token leakage in Referer",
    "Permissions-Policy": "🔵 Controls access to hardware",
}

r = requests.get(TARGET, verify=False, timeout=10)
headers = {k.lower(): v for k, v in r.headers.items()}

print(f"=== HTTP Security Headers — {TARGET} ===\n")
for header, description in REQUIRED_HEADERS.items():
    value = headers.get(header.lower())
    if value:
        print(f"✅  {header}: {value[:80]}")
    else:
        print(f"❌  {header} MISSING → {description}")
```

---

## 📌 References
- [[xss-cross-site-scripting]]
- [[csrf-websocket-hijacking-cswsh]]
- [[chain-exploit-butterfly-effect]]
- [SecurityHeaders.com](https://securityheaders.com/)
- [MDN CSP Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)