# Advanced WAF & Gateway Evasion Tactics

**Tags:** #high #waf #evasion #bypass #obfuscation
**OWASP:** A05:2021 Security Misconfiguration
**CVSS Base:** (Depends on bypassed payload)

---

## 📖 What it is

WAFs (Web Application Firewalls) and API Gateways rely on pattern matching and signature detection. Advanced evasion involves tricking the Gateway's parser into interpreting data differently than the final Application parser, causing malicious payloads to slip past edge protections.

---

## 🔍 `grep_search` Tactics (Application side logic)

```
urllib.parse.unquote
req.query
$_SERVER['QUERY_STRING']
Transfer-Encoding
Content-Type
Iconv
```

---

## 💣 Attack Category 1: HTTP Parameter Pollution (HPP)

HPP exploits how different web servers process multiple occurrences of the same parameter in a query string. If the WAF inspects one and the backend consumes the other, constraints are bypassed.

**Payload Request:**
`GET /api/user?id=123&id=SELECT+*+FROM+USERS`

**Language Parsing Differences:**
- **PHP/Ruby:** Uses the *last* parameter. (Receives `SELECT...`)
- **ASP.NET:** Concatenates parameters with a comma. (`123,SELECT...`)
- **Go/Node.js:** Returns an array. `["123", "SELECT..."]`

**Bypass Execution:** If the WAF only checks the *first* parameter (`123` is safe) but the backend (PHP) executes the *last* parameter, the SQL injection bypasses the WAF.

---

## 💣 Attack Category 2: Chunked Transfer Desync

By using `Transfer-Encoding: chunked`, an attacker breaks the payload into chunks. If the WAF doesn't fully reassemble the chunks before signature checking, the payload slips through.

**Payload Structure:**
```http
POST /api/upload HTTP/1.1
Transfer-Encoding: chunked

1
S
1
E
1
L
...
```
*(Constructs `SELECT` across multiple chunks)*

---

## 💣 Attack Category 3: Charset and Encoding Bypasses

Manipulating encoders/decoders between the Edge and the Backend.

**1. Unicode Normalization Bypass:**
Payload: `ﬁle` (Unicode character `U+FB01`) instead of `file`.
- WAF: Sees `ﬁle`, checks signature, passes.
- Backend App: Normalizer converts `ﬁle` -> `file`. Executes payload.

**2. Null Byte Injection:**
Payload: `%00<script>alert(1)</script>`
- WAF: Reads until the null byte, concludes it's safe.
- Backend App: Ignores null byte, executes `<script>`.

### [NEW] Rate Limit Bypass via Header Variance
**How it works:** Many WAFs/Gateways track IP-based rate limits using `X-Forwarded-For`. Sending a unique IP in this header (or `X-Real-IP`, `X-Originating-IP`) for each request can bypass the limit.

### [NEW] Unicode-to-ASCII Collisions
**How it works:** Some systems normalize Unicode characters down to ASCII. 
**Example:** `ⓈⒺⓁⒺⒸⓉ` (U+24CE etc.) might be normalized to `SELECT`.
**Bypass:** WAF doesn't recognize the circled letters, but the DB engine normalizes them and executes the query.

### [NEW] Path Fragmentation
**Payload:** `/api/v1/user/..;/..;/admin`
**Effect:** Confuses path-based WAF rules while reaching the administrative endpoint on specific Java/Spring backends.

---

## 🛡️ Fix

1. **Strict Content-Type Validation:** Reject non-standard content-types and unexpected character sets.
2. **First-Hit Parsing Rule:** Frameworks should explicitly standardize on how duplicate parameters are handled inside middleware.
3. **Canonicalization:** The backend must parse and canonicalize input identical to what the WAF analyzes.

---

## 📌 References
- [[http-request-smuggling]]
- [OWASP Evasion Techniques](https://owasp.org/www-community/attacks/WAF_Evasion_Techniques)
