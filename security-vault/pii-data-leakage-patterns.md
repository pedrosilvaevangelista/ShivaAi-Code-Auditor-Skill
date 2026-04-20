# PII Data Leakage Patterns — Elite Detection Protocol

> **Context:** PII leakage is classified as a foundational breach. The attacker doesn't need to actively exploit a vulnerability — the application volunteers the data through misconfigured logging, verbose error responses, over-scoped API outputs, and metadata exposure.

**Tags:** #high #pii #privacy #leakage #gdpr #information-disclosure
**OWASP:** A02:2021 Cryptographic Failures / A04:2021 Insecure Design
**CVSS Base:** 5.3–8.0 (escalates rapidly when chained)

---

## The 6 PII Leakage Surfaces

### 1. Logging Sinks (Most Common)
Developers log entire objects for debugging and never remove those logs.

**Vulnerable patterns:**
```javascript
// Node.js — exposes password hash, email, token
logger.info("User registered:", JSON.stringify(newUser));

// Python — exposes the full request body
logging.debug(f"Processing request: {request.json()}")
```

**`grep_search`:** `console.log(user`, `logger.info(req`, `print(data`, `logging.debug(request`, `log.info(body`.

**Escalation:** If logs are centralized in ELK/Splunk/CloudWatch and accessible to many internal users, a single debug statement becomes a mass PII breach.

---

### 2. Verbose Error Messages (User Enumeration Gateway)

Error messages that differ based on data state leak information about the internal model.

**Classic PII leak via error:**
```
# VULNERABLE — reveals email existence
IntegrityError: UNIQUE constraint failed: users.email
```
```
# VULNERABLE — reveals username validity
"The password you entered for the username 'pedro' is incorrect"
vs.
"No account found with that email address"
```

**`grep_search`:** `e.message`, `exception.detail`, `raw_exception`, `error.stack`, `e.printStackTrace()`. Absence of a generic error-handling middleware is the structural flaw.

---

### 3. Over-Scoped API Responses (Mass Assignment Inverse)
APIs return the full ORM model without field selection, exposing internal fields.

**Vulnerable pattern:**
```python
# Django — serializes the entire User model
return Response(UserSerializer(request.user).data)
# Exposes: password (hash), is_staff, last_login, etc.
```

**`grep_search`:** `Serializer(`, `.to_dict()`, `jsonify(user)`, `JSON.stringify(model)`. Check if `.exclude(password)` or `fields = [...]` limits exposure.

---

### 4. HTTP Response Headers Leaking Internal Data

Verbose headers expose: backend technology, framework version, internal server names.

**Dangerous headers:** `Server: Apache/2.4.10 (Ubuntu)`, `X-Powered-By: Express`, `X-AspNet-Version`, `Via: internal-proxy-01.company.local`.

**`grep_search`:** `res.removeHeader('X-Powered-By')` (absence = leak). `app.disable('x-powered-by')` (absence = Express leak).

---

### 5. Client-Side Storage of PII (LocalStorage/SessionStorage)
Applications cache user data in the browser for performance.

**Vulnerable patterns:**
```javascript
// Stores entire profile including DOB, address, etc.
localStorage.setItem('userProfile', JSON.stringify(response.data));
```

**`grep_search`:** `localStorage.setItem(`, `sessionStorage.setItem(`. Verify what data is being stored; tokens are acceptable, PII is not.

---

### 6. URL Parameter PII Leakage (Logs + Referer)
Sensitive data passed in GET parameters is captured by web servers, CDN access logs, and the browser's Referer header.

**Vulnerable patterns:**
```
GET /api/users?email=pedro@example.com&ssn=123-45-6789 HTTP/1.1
Referer: https://trustedsite.com/search?query=pedro@example.com
```

**`grep_search`:** Routes where `req.query` or `$_GET` contains `email`, `ssn`, `cpf`, `phone`, `token`.

---

## Chained Exploitation Paths

```
PII in Logs + SSRF to Log Service → Mass credential harvesting
Verbose Error + User Enumeration + Brute Force → Account takeover at scale
Over-scoped API + IDOR → Full profile dump of any user
Header Leakage (X-Powered-By) + Known CVE for that version → RCE
```

---

## Strategic Checklist for Auditor
1. [ ] Trace every log statement to identify what data is logged.
2. [ ] Verify error responses are generic (no stack traces, no field names).
3. [ ] Read API serializers/transformers and check for field exclusion.
4. [ ] Grep all GET route parameters for PII fields.
5. [ ] Check for `app.disable('x-powered-by')` or `res.removeHeader('Server')`.

---

*Tags: #pii #data-leakage #information-disclosure #gdpr #compliance #shiva-vault*
