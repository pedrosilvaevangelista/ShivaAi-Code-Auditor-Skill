# Insecure Password Hashing

**Tags:** #high #hashing #password #rainbow-table #brute-force
**OWASP:** A02:2021 Cryptographic Failures
**CVSS Base:** 7.5 (High → credentials crackable in minutes with GPU)

---

## 📖 What is it

The choice of password hashing algorithm defines the system's resistance against an attacker who obtains the database. Fast algorithms (MD5, SHA-1, SHA-256) can be cracked on GPU at billions of attempts per second. Correct password algorithms add deliberate computational cost.

---

## 📊 Algorithm Comparison Table

| Algorithm | Status | Speed (GPU) | Resistance |
|---|---|---|---|
| MD5 | 🔴 FORBIDDEN | ~200 GB/s | None |
| SHA-1 | 🔴 FORBIDDEN | ~100 GB/s | None |
| SHA-256 without salt | 🔴 FORBIDDEN | ~10 GB/s | Rainbow tables: 0 |
| SHA-256 with salt | 🟠 INSUFFICIENT | ~10 GB/s | Brute force still trivial |
| MD5-crypt ($1$) | 🟠 INSUFFICIENT | ~500 MH/s | Outdated |
| SHA-512-crypt ($6$) | 🟡 LIMITED | ~5 MH/s | Linux only |
| **bcrypt** | ✅ SECURE | ~184 kH/s | Adjustable work factor |
| **argon2id** | ✅ PREFERRED | ~800 H/s | Memory+CPU-hard |
| **scrypt** | ✅ SECURE | ~1 kH/s | Memory-hard |
| **PBKDF2** | ✅ ACCEPTABLE | ~200 kH/s | NIST approved |

---

## 🔍 `grep_search` Tactics

```
hashlib.md5
hashlib.sha1
hashlib.sha256
md5(
sha1(
sha256(
password_hash.*md5
password_hash.*sha
MessageDigest.getInstance.*MD5
MessageDigest.getInstance.*SHA-1
MessageDigest.getInstance.*SHA1
```

---

## 💣 Vulnerable Patterns

### Python

```python
#  VULNERABLE — MD5 without salt
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()

#  VULNERABLE — SHA256 without salt (rainbow table)
hashed = hashlib.sha256(password.encode()).hexdigest()

#  VULNERABLE — SHA256 with salt but no cost
salt = os.urandom(16)
hashed = hashlib.sha256(salt + password.encode()).hexdigest()
# → Crackable in minutes with GPU
```

### PHP

```php
//  VULNERABLE — MD5
$hash = md5($password);  // crackable in milliseconds

//  VULNERABLE — SHA1
$hash = sha1($password);

//  VULNERABLE — MD5 with manual salt (still fast)
$hash = md5($salt . $password);
```

### Java

```java
//  VULNERABLE
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes());

//  VULNERABLE — SHA-1
MessageDigest sha = MessageDigest.getInstance("SHA-1");
```

### JavaScript / Node.js

```javascript
//  VULNERABLE
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');
const hash2 = crypto.createHash('sha256').update(password).digest('hex');
```

---

## ✅ Correct Implementations

### Python — bcrypt (preferred for simplicity)

```python
#  CORRECT
import bcrypt

def hash_password(password: str) -> str:
    # gensalt(rounds=12) → work factor (2^12 iterations)
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
```

### Python — argon2id (best modern choice)

```python
#  CORRECT — argon2-cffi
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(
    time_cost=2,        # number of iterations
    memory_cost=65536,  # 64 MB of memory
    parallelism=2,      # parallel threads
    hash_len=32,
    salt_len=16,
)

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(hashed: str, password: str) -> bool:
    try:
        return ph.verify(hashed, password)
    except VerifyMismatchError:
        return False
```

### PHP

```php
//  CORRECT — password_hash with bcrypt
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

//  CORRECT — password_hash with argon2id (PHP 7.3+)
$hash = password_hash($password, PASSWORD_ARGON2ID);

// Verify
if (password_verify($input_password, $stored_hash)) {
    // authenticated
}
```

### Java — Spring Security

```java
//  CORRECT — BCryptPasswordEncoder
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);  // strength=12
String hashed = encoder.encode(rawPassword);
boolean matches = encoder.matches(rawPassword, hashed);
```

### Node.js

```javascript
//  CORRECT — bcrypt
const bcrypt = require('bcrypt');

async function hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}
```

---

## 🧪 Hash Analysis Script

```python
# .tmp/analyze_hash.py — Identify hash types in the database
# DISCARD AFTER USE

import re, sys

def identify_hash(hash_str: str) -> str:
    """Identifies the hash type by format."""
    if hash_str.startswith('$2b$') or hash_str.startswith('$2a$') or hash_str.startswith('$2y$'):
        cost = int(hash_str.split('$')[2])
        return f"bcrypt (cost={cost}) {'✅ SECURE' if cost >= 10 else '⚠️ LOW COST'}"
    elif hash_str.startswith('$argon2id$'):
        return "argon2id ✅ SECURE"
    elif hash_str.startswith('$argon2i$') or hash_str.startswith('$argon2d$'):
        return "argon2 (non-id) ⚠️ USE argon2id"
    elif hash_str.startswith('$6$'):
        return "SHA-512-crypt (Linux) 🟡 OK but not ideal"
    elif hash_str.startswith('$1$'):
        return "MD5-crypt 🔴 INSECURE"
    elif re.match(r'^[0-9a-f]{32}$', hash_str):
        return "MD5 (no salt) 🔴 CRITICAL"
    elif re.match(r'^[0-9a-f]{40}$', hash_str):
        return "SHA-1 🔴 INSECURE"
    elif re.match(r'^[0-9a-f]{64}$', hash_str):
        return "SHA-256 🟠 TOO FAST for passwords"
    elif re.match(r'^[0-9a-f]{128}$', hash_str):
        return "SHA-512 🟠 TOO FAST for passwords"
    else:
        return "Unknown → verify manually"

# Examples
test_hashes = [
    "5f4dcc3b5aa765d61d8327deb882cf99",  # MD5 of "password"
    "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8JBIXIJDWMQR7NwDvS",  # bcrypt
    "$argon2id$v=19$m=65536,t=2,p=2$...",
]

for h in test_hashes:
    print(f"{h[:30]}...  {identify_hash(h)}")
```

---

## 🔗 Chain Exploits

```
MD5/SHA1 password + database leak → Cracked in minutes with hashcat + GPU
SHA256 without salt + public database → Instant rainbow table lookup
Bcrypt with low cost (< 10) → Accelerated brute force
Identical hash for the same password → Users sharing passwords are detectable
Password in error log → Direct compromise without hash cracking
```

---

## 📌 References
- [[systemic-cryptography-flaws]]
- [[authentication-session-management]]
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)