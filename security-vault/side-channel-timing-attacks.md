# Side-Channel Timing Attacks — Tactical Pillar

> **Context:** The application takes a different amount of time to process a request depending on the input provided. Even milliseconds of difference can leak deterministic information about the underlying data (passwords, API keys, usernames).

---

## 1. User Enumeration (Login/Reset Flows)
A classic timing attack where the application takes exponentially longer to process a login if the user exists (due to bcrypt/scrypt hashing) than if the user does not exist.
- **Tactic:** Attacker measures the response time of `POST /login` for `admin@company.com` vs `fake@fake.com`. If `admin@company.com` systematically takes ~200ms longer, the attacker confirms the account exists.
- **Audit Requirement:**
  - Standardize response time. If user does not exist, compute a dummy hash to balance the time.
- **`grep_search`:** `bcrypt.compare`, `argon2.verify`, `/login`, `/forgot-password`.

## 2. Insecure String Comparison (HMAC/API Key)
Using standard string comparison operators (`==`, `!=`, `===`) to compare cryptographic hashes or API keys.
- **The Flaw:** Standard comparison exits on the first mismatched byte.
  - `admin_key == "AAAA"` (Fails on 1st byte -> 1ms)
  - `admin_key == "SDAA"` (Fails on 1st byte -> 1ms)
  - `admin_key == "SECR"` (Fails on 4th byte -> 4ms)
- **Tactic:** Attacker brute-forces the key byte-by-byte, measuring the macro-timing differences to guess the secret iteratively.
- **Correction:** Use constant-time comparison methods.
- **`grep_search`:** 
  - Python: `hmac.compare_digest(` (Absence of this is a flaw).
  - Node.js: `crypto.timingSafeEqual(`.
  - PHP: `hash_equals(`.

## 3. JWT Signature Timing Attack
Some poorly implemented JWT libraries validate the signature byte-by-byte via standard string comparison.
- **Tactic:** Attacker submits a forged JWT and measures the time it takes the server to reject it. By adapting the signature one byte at a time, they forge a valid signature without the key.
- **Audit:** Ensure updated validation libraries.

## Strategic Checklist
1. [ ] Check login/reset logic for dummy hash fallback.
2. [ ] Identify API key and webhook secret validation.
3. [ ] Trace string comparisons acting as authorization guards.
4. [ ] Propose the replacement of standard equality checks with `timingSafeEqual`.

---
*Tags: #side-channel #timing-attack #cryptography #enumeration #shiva-vault*
