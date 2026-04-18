# Cryptography — Systemic Failures

**Tags:** #high #cryptography #hashing #randomness #tls #secrets
**OWASP:** A02:2021 Cryptographic Failures
**CVSS Base:** 7.5 (High) — 9.1 (Critical — exposed private keys)

---

## 📖 What it is

Cryptographic weaknesses are silent — the system works, but security is illusory. An attacker obtains "protected" data without needing a technical breach.

---

## 🔍 `grep_search` Tactics

```
# Insecure password hashing
md5(
sha1(
sha256(
hashlib.md5
hashlib.sha1
hashlib.sha256

# Hardcoded secrets
SECRET_KEY =
API_KEY =
password =
PRIVATE_KEY =
AWS_ACCESS_KEY_ID =
DATABASE_URL =
token =

# Insecure randomness
Math.random()
random.random()
random.randint
rand()

# Disabled TLS
verify=False
rejectUnauthorized: false
CURLOPT_SSL_VERIFYPEER
ssl_verify = False

# Weak cipher modes
AES/ECB
Cipher.getInstance("AES")
DES
RC4
MD5WithRSA
```

---

## 💣 Audits by Category

### 1. Insecure Password Hashing

| Algorithm | Status | Reason |
|---|---|---|
| `MD5` | 🔴 FORBIDDEN | Trivial collisions, public rainbow tables |
| `SHA1` | 🔴 FORBIDDEN | Collision demonstrated (SHAttered) |
| `SHA256` without salt | 🟠 INSECURE | No computational cost, rainbow tables |
| `SHA256` with salt | 🟡 INADEQUATE | Too fast — GPU cracks at 10GB/s |
| `bcrypt` | ✅ SECURE | Adjustable work factor, built-in salt |
| `argon2id` | ✅ PREFERRED | Password Hashing Competition winner |
| `scrypt` | ✅ SECURE | Memory-hard, resists GPU attacks |
| `pbkdf2` | ✅ ACCEPTABLE | Secure with high iteration count (>600k) |

```python
#  VULNERABLE
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()
hashed = hashlib.sha256(password.encode()).hexdigest()

#  CORRECT  bcrypt
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
is_valid = bcrypt.checkpw(password.encode(), hashed)

#  CORRECT  argon2id
from argon2 import PasswordHasher
ph = PasswordHasher()
hashed = ph.hash(password)
ph.verify(hashed, password)
```

---

### 2. Hardcoded Secrets

```python
#  CRITICAL  secret in code (versioned in git)
SECRET_KEY = "super_secret_dev_key_123"
DB_PASSWORD = "admin123"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

**Impact:** anyone with access to the repository (including former employees, contributors, leaks) has the secret. Secrets in git never die — they remain in history even after removal.

```python
#  CORRECT  environment variables
import os
SECRET_KEY = os.environ['SECRET_KEY']
DB_PASSWORD = os.environ['DATABASE_PASSWORD']
```

**Detection tools:**
- `git secret` / `detect-secrets` / `gitleaks`
- `git log -p | grep -i password`

---

### 3. Insecure Randomness in Critical Contexts

```python
#  VULNERABLE  random.random() is deterministic (seeded)
import random
token = str(random.random())            # predictable
reset_token = random.randint(0, 999999) # brute-forceable in minutes
csrf_token = hex(random.getrandbits(32)) # insecure

#  CORRECT  CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
import secrets
token = secrets.token_hex(32)           # 256 bits of real entropy
reset_token = secrets.token_urlsafe(32) # URL-safe
csrf_token = secrets.token_bytes(32)
```

```javascript
//  VULNERABLE
const token = Math.random().toString(36);

//  CORRECT  Node.js
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
```

```java
//  VULNERABLE
Random r = new Random();
int token = r.nextInt();

//  CORRECT
SecureRandom sr = new SecureRandom();
byte[] token = new byte[32];
sr.nextBytes(token);
```

---

### 4. Weak Cipher Modes

#### ECB (Electronic Code Book) — Pattern Preservation

```python
#  VULNERABLE  ECB reveals patterns in data
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)

#  CORRECT  GCM (authenticated + non-deterministic)
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
nonce = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
```

**ECB visual vulnerability:**
> Imagine encrypting a bitmap image with ECB vs GCM.  
> With ECB, the Tux Linux penguin is **visible** even when encrypted — identical blocks produce identical ciphertext.

#### Reused IV/Nonce in CBC/GCM

```python
#  VULNERABLE  fixed IV = deterministic cipher
FIXED_IV = b'\x00' * 16
cipher = AES.new(key, AES.MODE_CBC, FIXED_IV)  # NEVER reuse IV

#  CORRECT  random IV per operation
iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
# Send iv concatenated with ciphertext

### [NEW] Padding Oracle Attack (CBC Mode)
**How it works:** If the server reveals whether a decrypted message has valid padding (e.g., via different error messages or timing), an attacker can decrypt the ciphertext block-by-block without the key.
**Detection:** Look for custom decryption logic and error handlers that distinguish between "invalid padding" and "MAC mismatch".

### [NEW] Timing Attacks (String Comparison)
**How it works:** Normal string comparison (`==`) returns as soon as it finds a mismatch. An attacker can measure the time taken to guess a secret (like an API key) character-by-character.
**Fix:** Always use constant-time comparison libraries.
```python
#  CORRECT
import hmac
is_valid = hmac.compare_digest(provided_token, secret_token)
```
```

---

### 5. Disabled TLS/SSL

```python
#  CRITICAL  trivial MitM
import requests
r = requests.get('https://api.target.com', verify=False)

#  CRITICAL  Python urllib
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE  # verifies nothing
```

```javascript
//  CRITICAL  Node.js
const https = require('https');
const agent = new https.Agent({ rejectUnauthorized: false });
```

---

### 6. Short Key Lengths

| Algorithm | Minimum Secure Length |
|---|---|
| RSA | 2048 bits (prefer 4096) |
| ECDSA | 256 bits (P-256) |
| AES | 128 bits minimum (prefer 256) |
| DH Key | 2048 bits |

```
DES (56 bits)  BROKEN in hours
3DES  BROKEN (SWEET32 attack  CVE-2016-2183)
RSA-1024  INSECURE (breakable by nation-states)
```

---

## 🔗 Chain Exploits

```
MD5 password hash + database leak  Instant cracking via rainbow table
Hardcoded secret + public GitHub  Immediate compromise without intrusion
Disabled TLS + public network  MitM with credential interception
Math.random() in reset token  Token brute force  Account takeover
ECB mode + predictable data  Content inference without breaking the key
```

---

## 📌 References
- [[insecure-password-hashing]]
- [[jwt-algorithm-confusion-attacks]]
- [[authentication-session-management]]
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)