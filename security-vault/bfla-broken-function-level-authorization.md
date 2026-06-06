# BFLA & Force Browsing — Broken Function Level Authorization

**Tags:** #high #bfla #access-control #force-browsing #api #privilege-escalation
**OWASP:** A01:2025 Broken Access Control / API5:2023 BFLA
**CVSS Base:** 8.5 (High → Privilege Escalation, unauthorized administrative actions)

---

## 📖 What is it

**Broken Function Level Authorization (BFLA):** occurs when an application or API does not properly verify if the authenticated user has the necessary permissions (roles/privileges) to execute a specific function.

While BOLA (IDOR) involves accessing another user's *data* (objects), BFLA involves executing another user's *actions* (functions), usually administrative or privileged ones.

**Force Browsing (CWE-425):** A common manifestation of BFLA where an attacker simply guesses or discovers administrative URLs or API endpoints and accesses them directly, bypassing the UI flow.

---

## 🎯 OWASP 2025 Scenarios

### Scenario #1: Force Browsing (CWE-425)
Admin rights are required for access to the admin page.
- `https://example.com/app/getappInfo` (Standard User)
- `https://example.com/app/admin_getappInfo` (Admin User)
If an unauthenticated user or a non-admin user can directly browse to `admin_getappInfo` and access it, this is a BFLA/Force Browsing flaw.

### Scenario #2: Missing Backend API Access Control
An application puts all of its access control in the front-end (UI). The frontend hides the "Delete User" button for non-admins. However, the attacker uses `curl` to directly hit the API:
`$ curl -X DELETE https://example.com/api/admin/users/123 -H "Authorization: Bearer <standard_token>"`
Since the backend API lacks role validation for the `DELETE` method, the action succeeds.

---

## 🔍 `grep_search` Tactics

```
# Look for admin/privileged routes
/admin/
/api/v1/admin
/superuser/
/manage/
Role.ADMIN

# Look for sensitive HTTP methods without guards
app.post(
app.delete(
app.put(
@DeleteMapping(
@PutMapping(

# Look for role checks (or lack thereof)
isAdmin
hasRole(
checkPermissions(
```

**What to look for:** Sensitive routes or methods (POST, DELETE, PUT) that verify authentication (`isAuthenticated()`) but fail to verify authorization (`hasRole('ADMIN')`).

---

## 💣 Vulnerable Patterns

```javascript
//  VULNERABLE — Express (Missing Role Check)
// Authentication is checked, but Authorization is missing!
app.delete('/api/users/:id', verifyToken, async (req, res) => {
    // req.user exists, but we didn't check if req.user.role === 'admin'
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});
```

```java
//  VULNERABLE — Spring Boot (Missing @PreAuthorize)
@RestController
@RequestMapping("/api/admin")
public class AdminController {
    
    // Only hidden in UI, but accessible if hit directly
    @GetMapping("/system-logs")
    public ResponseEntity<String> getLogs() {
        return ResponseEntity.ok(sysLogs);
    }
}
```

---

## ✅ Correct Patterns

```javascript
//  CORRECT — Express
// Using a specific middleware for authorization
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).send("Forbidden");
    next();
};

app.delete('/api/users/:id', verifyToken, requireAdmin, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});
```

```java
//  CORRECT — Spring Boot
@RestController
@RequestMapping("/api/admin")
public class AdminController {
    
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/system-logs")
    public ResponseEntity<String> getLogs() {
        return ResponseEntity.ok(sysLogs);
    }
}
```

---

## 💣 Exploit Techniques

### 1. HTTP Verb Tampering — The Forgotten Method Matrix
When a single route handles multiple HTTP methods, access control is often only applied to the most obvious one.

```
# The target endpoint
GET    /api/admin/users    → 403 Forbidden  (protected)
POST   /api/admin/users    → 201 Created    (BFLA! POST not checked)
DELETE /api/admin/users/5  → 403 Forbidden  (protected)
PUT    /api/admin/users/5  → 200 OK         (BFLA! PUT not checked)
PATCH  /api/admin/users/5  → 200 OK         (BFLA! PATCH not checked)
```

**Protocol:** For every protected endpoint, try all 7 HTTP methods: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS. Test also with `X-HTTP-Method-Override: DELETE` header for backends that honor it.

```bash
# Systematic HTTP method enumeration
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo "[$method] $(curl -s -o /dev/null -w '%{http_code}' -X $method \
    http://target.com/api/admin/users \
    -H 'Authorization: Bearer <standard_user_token>')"
done
```

### 2. URL Path Manipulation (Force Browsing)
Adding or modifying path segments to reach administrative controllers.
```
/api/users/v1            →  /api/admin/v1
/api/v1/users/export     →  /api/v1/users/exportAll
/api/v2/reports/mine     →  /api/v2/reports/all
/app/user/dashboard      →  /app/admin/dashboard
```

**Versioned API Bypass:** When `v2` is secured but `v1` is forgotten:
```
GET /api/v2/admin/users   → 403 (properly guarded)
GET /api/v1/admin/users   → 200 (legacy endpoint, no auth!)
```
**`grep_search`:** Map all version-prefixed routes. Old API versions are a primary target.

### 3. GraphQL BFLA — Field-Level Authorization Bypass
In GraphQL, role checks are often implemented at the resolver level. If field-level resolvers don't inherit the root check:

```graphql
# Standard user makes this query:
query {
  me {
    email
    # These admin fields should be forbidden, but the resolver lacks @auth
    adminNotes
    allUsersCount
    systemConfiguration { debug apiKey }
  }
}
```

**`grep_search`:** Look for `@auth`, `@access`, `hasRole` decorators. If a resolver function lacks these but returns sensitive data, it is a BFLA.

### 4. JWT Claim Manipulation (Role Escalation via Decode-Modify-Re-encode)
If the JWT uses `alg: none` or a weak HMAC secret:
```bash
# Decode the token
echo '<base64_payload>' | base64 -d | jq
# {"sub": "123", "role": "user"}

# Modify and re-encode (if alg: none is accepted)
python3 -c "
import jwt, json, base64
header = base64.b64decode('eyJhbGciOiJub25lIn0=')
payload = {'sub': '123', 'role': 'admin'}  # Escalated!
token = jwt.encode(payload, '', algorithm='none')
print(token)
"
```

**`grep_search`:** `algorithms=['none']`, `verify=False`, `options={"verify_signature": False}` in JWT verification code.

## 🔗 Chain Exploits

```
BFLA (GET /admin/users) + User Enumeration → Targeted Credential Stuffing
HTTP Verb Tampering (DELETE) + IDOR (ID manipulation) → Mass User Account Deletion
GraphQL BFLA (systemConfiguration field) + Exposed API Key → Lateral Movement to 3rd-party SaaS
JWT role escalation + BFLA → Full Admin Takeover without authentication bypass
Legacy API version + BFLA → Unprotected admin functions with no rate limit
```

---

## 📌 References
- [OWASP A01:2025 Broken Access Control](https://owasp.org/Top10/)
- [[idor-bola-broken-object-level-authorization]]
- [[mass-assignment]]
- [[jwt-algorithm-confusion-attacks]]
