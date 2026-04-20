# Side-Channel Timing Attacks — Elite Detection Protocol

> **Context:** The application's processing time is not constant — it varies based on the input. This deterministic variance leaks information about internal data (password length, username validity, API key prefix, cryptographic secret bytes) enabling byte-by-byte brute force without touching rate limits.

**Tags:** #high #timing #side-channel #cryptography #enumeration #bypass
**OWASP:** A02:2021 Cryptographic Failures / A07:2021 Identification and Authentication Failures
**CVSS Base:** 5.3–7.5 (escalates with target sensitivity)

---

## The Core Principle: Early-Exit Comparisons

Standard equality operators (`==`, `===`, `equals()`) exit immediately on the first mismatched byte. This creates a timing oracle:

```
Comparing "SECRETKEY" against guess:
"AXXXXXXXX" → mismatch at byte 1 → returns in ~0.001ms
"SXXXXXXXX" → mismatch at byte 2 → returns in ~0.002ms
"SEXXXXXXX" → mismatch at byte 3 → returns in ~0.003ms
```

Over thousands of measurements, the attacker distinguishes microsecond deltas and reconstructs the secret byte-by-byte.

---

## Attack Surfaces by Category

### 1. Login / Password Reset — User Enumeration via Timing

**The architectural flaw:** bcrypt/argon2 are deliberately slow (~200ms). If the code only runs the hash computation when the user *exists*, non-existent users respond in ~0ms while valid users respond in ~200ms.

**Vulnerable pattern:**
```python
user = db.find_user(email)
if not user:
    return "Invalid credentials"   # Returns immediately — reveals user non-existence
if not bcrypt.check(user.password, request.password):
    return "Invalid credentials"   # Returns in 200ms — reveals user existence
```

**Secure pattern:**
```python
user = db.find_user(email)
dummy_hash = "$2b$12$notarealhashbutlengthmatch"
hash_to_check = user.password_hash if user else dummy_hash
bcrypt.check(hash_to_check, request.password)  # Always runs — timing equalized
if not user or not result:
    return "Invalid credentials"
```

**`grep_search`:** `if not user: return`, `user is None: raise`, `/login`, `/forgot-password`, `findByEmail`. Trace whether the hash function is called on the **same code path** regardless of user existence.

---

### 2. HMAC / API Key / Webhook Secret Comparison

Using standard `==` to compare HMAC signatures or API keys.

**Vulnerable patterns (language-specific):**

```python
# Python — VULNERABLE
if request.headers['X-Signature'] == compute_hmac(body):

# Node.js — VULNERABLE
if (req.headers['x-webhook-secret'] === process.env.WEBHOOK_SECRET)

# PHP — VULNERABLE
if ($_POST['api_key'] === $stored_key)
```

**Exploit:** Attacker sends thousands of requests with different first bytes. The prefix that produces the longest average response time is the correct byte. Recurse for each position.

**Secure replacements:**
| Language | Constant-Time Function |
|---|---|
| Python | `hmac.compare_digest(a, b)` |
| Node.js | `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))` |
| PHP | `hash_equals($known_string, $user_string)` |
| Java | `MessageDigest.isEqual(a, b)` |
| Go | `subtle.ConstantTimeCompare(a, b)` |
| Ruby | `ActiveSupport::SecurityUtils.secure_compare(a, b)` |

**`grep_search`:** Search for absence of the above. Any comparison of security-critical strings using `==`, `===`, `equals()`, `.compareTo()` is the vulnerability.

---

### 3. JWT / Token Signature Timing Attack

**The scenario:** JWT validation libraries that compare signatures using standard string equality.

**Attack chain:**
1. Decode the JWT structure (public `alg`, `sub` fields visible in base64).
2. Forge a JWT with a known signing key attempt.
3. Send it to the endpoints that validate it.
4. Measure response time to determine how many signature bytes match.
5. Iterate until a valid signature is forged **without knowing the secret**.

**`grep_search`:** `jwt.verify(`, `JWT.decode(`. Verify the library version — libraries like `jsonwebtoken` before certain versions used non-constant-time comparison.

---

### 4. Two-Factor Authentication (OTP) Brute-Force via Timing

**The scenario:** OTP code validation using `==` comparison.

```javascript
// VULNERABLE
if (req.body.otp === user.currentOtp) { ... }
```

An attacker generating OTPs starting with `0` vs `9` can distinguish which prefix starts matching — reducing the keyspace from 10^6 to 10^6/10 per character.

**`grep_search`:** `otp ==`, `verificationCode ===`, `token ==` in MFA routes.

---

### 5. Database Timing via SQL (Boolean Blind + Sleep)

When the application doesn't return error messages, timing can still be exploited to exfiltrate data:

```sql
-- Causes 5s delay if admin password starts with 'S'
'; IF (SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='S') WAITFOR DELAY '0:0:5' --
```

**`grep_search`:** While this is a SQLi variant, look for endpoints with extremely variable response times in error conditions (not error-message-based SQLi).

---

## PoC Validation Script (Ephemeral `.tmp/`)

```python
import requests, time, statistics

TARGET = "https://target.com/login"
VALID_EMAIL = "admin@target.com"
FAKE_EMAIL = "notarealuser12345@fake.com"

def measure(email, iterations=50):
    times = []
    for _ in range(iterations):
        payload = {"email": email, "password": "wrongpassword"}
        start = time.perf_counter()
        requests.post(TARGET, json=payload)
        times.append(time.perf_counter() - start)
    return statistics.mean(times) * 1000  # ms

valid_avg = measure(VALID_EMAIL)
fake_avg = measure(FAKE_EMAIL)

diff = abs(valid_avg - fake_avg)
print(f"Valid user avg: {valid_avg:.2f}ms | Fake user avg: {fake_avg:.2f}ms | Delta: {diff:.2f}ms")
if diff > 50:
    print("[HIGH] Timing-based user enumeration confirmed (>50ms delta).")
```

---

## Chained Exploitation Paths

```
Timing Enumeration → Valid Username List → Credential Stuffing → Account Takeover
HMAC Timing → Webhook Signature Forgery → Arbitrary Webhook Payload Injection
JWT Timing → Signature Forgery → Authentication Bypass → Full Admin Access
OTP Timing → Reduced Brute-Force Space → MFA Bypass → Account Takeover
```

---

## Strategic Checklist for Auditor
1. [ ] Trace all login flows — does a hash function execute regardless of user existence?
2. [ ] Find HMAC/signature comparison code and verify it uses constant-time equality.
3. [ ] Check MFA/OTP validation code for standard equality operators.
4. [ ] Verify JWT library version for known non-constant-time comparison CVEs.
5. [ ] For DAST targets: run the `.tmp/` timing PoC to confirm delta empirically.

---

*Tags: #side-channel #timing-attack #user-enumeration #hmac #otp #jwt #shiva-vault*
