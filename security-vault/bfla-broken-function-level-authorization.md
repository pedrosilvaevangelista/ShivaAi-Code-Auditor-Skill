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

### 1. HTTP Method Tampering
Sometimes the `GET` endpoint is protected, but the `POST` or `PUT` endpoint to the same path is forgotten.
```bash
GET /api/admin/users -> 403 Forbidden
POST /api/admin/users -> 201 Created (BFLA!)
```

### 2. URL Path Manipulation (Force Browsing)
Adding or modifying path segments to reach administrative controllers.
```
/api/users/v1 -> /api/admin/v1
/api/v1/users/export -> /api/v1/users/exportAll
```

### 3. Parameter Pollution / Type Juggling
Changing the role directly in the request if the backend blindly accepts it (Mass Assignment crossover).
```json
// POST /api/register
{
  "email": "attacker@evil.com",
  "password": "pass",
  "role": "admin",
  "isAdmin": true
}
```

---

## 📌 References
- [OWASP A01:2025 Broken Access Control](https://owasp.org/Top10/)
- [[idor-bola-broken-object-level-authorization]]
- [[mass-assignment]]
