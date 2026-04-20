# PII Data Leakage Patterns

**Tags:** #high #pii #privacy #leakage #gdpr
**OWASP:** A02:2021 Cryptographic Failures / A04:2021 Insecure Design
**CVSS Base:** 5.3 (Medium) — 7.5 (High if total dump is possible)

---

## 📖 What it is

Data leakage occurs when Personally Identifiable Information (PII), such as emails, phone numbers, or credit card details, is exposed via non-standard channels like logs, debug outputs, or insecure API responses.

---

## 🔍 `grep_search` Tactics

```
console.log(user
print(data
logger.info(
Error(
Exception(
email
phone
address
PII
```

---

## 💣 Attack Category 1: Sensitive Data in Logs

**How it works:** Developers log the entire `user` object for debugging purposes, which ends up in centralized logging systems (ELK, CloudWatch) where many people have access.

**Vulnerable Patterns:**
```javascript
// VULNERABLE
logger.info("New user registered: " + JSON.stringify(newUser)); 
// Log contains password_hash, email, etc.
```

---

## 💣 Attack Category 2: Verbose Error Messages

**How it works:** Exception handlers return the raw database error or stack trace to the frontend.

**Example:**
`"IntegrityError: Duplicate entry 'pedro@example.com' for key 'users.email'"`
➔ Leaks that the user already exists (User Enumeration).

---

## 🛡️ Fix

1. **Redaction:** Use log-scrubbing libraries to mask emails and passwords.
2. **Generic Errors:** Always return "Internal Server Error" with a unique ID for log correlation.
3. **Filtering:** Explicitly filter objects before serialization: `const { password, ...userSafe } = user;`.

---

## 🔗 Chain Exploits

```
PII Leakage via Logs + Log Access ➔ Credential harvesting
PII Leakage + User Enumeration ➔ Account takeover targets
```
