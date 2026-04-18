# Business Logic Flaws

**Tags:** #high #business-logic #idor #race-condition #flow
**OWASP:** A04:2021 Insecure Design
**CVSS Base:** Variable → up to 9.8 (Critical → financial fraud, privilege escalation)

---

## 📖 What is it

Business Logic Flaws are vulnerabilities in the **intentional design** of the application — not in its code. No automated scanner detects them by definition; it requires simulating the role of a malicious user trying to subvert the intended flow.

> *"The scanner finds implementation vulnerabilities. The auditor finds design vulnerabilities."*

---

## 🧠 Key Auditor Questions

1. **"Can I skip a step in the flow?"** — Checkout without going through the cart? Admin without verifying 2FA?
2. **"Can I apply a negative discount?"** — Do quantity or price fields accept negative values?
3. **"Can I access another user's resource by changing an ID?"** — [[idor-bola-broken-object-level-authorization]]
4. **"Can I perform two simultaneous operations?"** — [[race-condition-toctou]]
5. **"Can I go directly to the final URL without completing the process?"** — Bypass of multi-step flows
6. **"What happens if I manipulate the assumed state?"** — Payment step cookie

---

## 💣 Vulnerability Patterns

### 1. Multi-Step Flow Bypass

```
Intended flow:
  /checkout/step1 (information)
   /checkout/step2 (address)
   /checkout/step3 (payment)
   /checkout/confirm

Attack: go directly to /checkout/confirm without completing the steps
→ Order without payment? Empty shipping address?
```

### [NEW] State Machine Bypasses
**How it works:** The application logic assumes a specific order of states (e.g., `DRAFT` -> `SUBMITTED` -> `PAID` -> `SHIPPED`).
**Attack:** Directly sending a state transition (e.g., `status=SHIPPED`) in a `PUT` request that should only be allowed by the internal system.

### [NEW] Rounding / Precision Errors
**How it works:** Vulnerabilities that occur during currency conversion or discount calculations (e.g., `0.005` being rounded down to `0` or up to `0.01`).
**Attack:** Performing thousands of small transactions to "shave off" fractions of a cent (Salami slicing).

**Protocol:** identify "confirmation" endpoints that do not verify the session/database state of previous steps.

---

### 2. Numeric Value Manipulation

```javascript
//  VULNERABLE — does not validate negative quantity
app.post('/cart/add', (req, res) => {
    const { product_id, quantity } = req.body;
    // quantity can be -100!
    cart.add(product_id, quantity);  // infinite discount
});
```

```python
#  VULNERABLE — discount field controlled by the user
@app.post('/apply-coupon')
def apply_coupon():
    discount = float(request.json['discount'])
    # Negative = price increase, or huge number = negative total
    order.total -= discount
```

---

### 3. Privilege Escalation via Hidden Parameter

```http
POST /api/register HTTP/1.1
Content-Type: application/json

{
    "email": "attacker@evil.com",
    "password": "hunter2",
    "role": "admin",         → try adding this field
    "is_admin": true,
    "verified": true
}
```

→ See also: [[mass-assignment]]

---

### 4. Coupon/Voucher Abuse

```
10% discount coupon, reusable:
→ Use the same coupon in 1000 simultaneous orders (Race Condition)
→ Use coupon on itself (coupon on the coupon's discount)
→ Coupon for "new user" but account registered years ago — validation by email only?
→ Predictable coupon code (SEQ-001, SEQ-002... try SEQ-1000)
```

---

### 5. Authorization Logic Only on the Frontend

```javascript
// React frontend — "Delete" button hidden for non-admins
{userRole === 'admin' && <button onClick={deleteUser}>Delete</button>}

// Backend — no corresponding check
app.delete('/api/users/:id', async (req, res) => {
    await User.delete(req.params.id);  //  any authenticated user can do this via curl!
    res.json({ success: true });
});
```

**Protocol:** for each action protected on the frontend, verify whether the backend also checks it.

---

### 6. Abusable Refund/Chargeback

```
Flow: Purchase → product arrives → request refund

Attack:
1. Request refund before the product is delivered
2. Request refund and keep the product (if there is no return verification)
3. Partial refund = negative credit that becomes a positive balance
```

---

### 7. Business Rule Enumeration

```
"Premium user has access to advanced reports"
→ Check: does the backend verify the 'premium' flag on EACH request?
→ Or is the flag stored in an unsigned cookie?

Attack: modify the cookie
document.cookie = "plan=premium"; // or via DevTools
→ If the backend trusts the cookie → free premium access
```

---

## 🔍 `grep_search` Tactics

```
# State checks in the flow
step
stage
phase
completed
verified
is_admin
role
premium
plan

# Numeric values without range validation
quantity
discount
amount
price
balance
credit
```

---

## 🧪 Flow Analysis Checklist

```
For each relevant business functionality:

[ ] Does the backend validate ALL steps of the flow, or does it trust the frontend?
[ ] Do numeric parameters accept negative values? Very large values?
[ ] Are sensitive operations atomic (transactions)? → Race Condition
[ ] Is the "authorized" state verified server-side on each request?
[ ] Are coupons/vouchers invalidated after single use?
[ ] Do irreversible operations have server-side confirmed verification?
[ ] Can role/admin fields be sent and accepted by the backend?
[ ] Do authorization flags live in unsigned cookies?
```

---

## 🔗 Chain Exploits

```
Multi-step flow bypass + payment = Purchases without paying
Negative quantity + checkout = Account credit
Frontend-only logic + admin action = Trivial privilege escalation
Coupon abuse + Race Condition = Infinite discount
role= parameter + Mass Assignment = Admin without special registration
```

---

## 📌 References
- [[mass-assignment]]
- [[race-condition-toctou]]
- [[idor-bola-broken-object-level-authorization]]
- [OWASP Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)