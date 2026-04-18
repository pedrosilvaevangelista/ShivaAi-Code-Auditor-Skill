# Criptografia  Falhas Sistemáticas

**Tags:** #alto #criptografia #hashing #aleatoriedade #tls #segredos
**OWASP:** A02:2021  Cryptographic Failures
**CVSS Base:** 7.5 (Alto)  9.1 (Crítico  chaves privadas expostas)

---

## 📖 O que é

Fraquezas criptográficas são silenciosas  o sistema funciona, mas a segurança é ilusória. Um atacante obtém dados "protegidos" sem precisar de invasão técnica.

---

## 🔍 `grep_search` Táticas

```
# Hashing inseguro de senhas
md5(
sha1(
sha256(
hashlib.md5
hashlib.sha1
hashlib.sha256

# Segredos hardcoded
SECRET_KEY =
API_KEY =
password =
PRIVATE_KEY =
AWS_ACCESS_KEY_ID =
DATABASE_URL =
token =

# Aleatoriedade insegura
Math.random()
random.random()
random.randint
rand()

# TLS desabilitado
verify=False
rejectUnauthorized: false
CURLOPT_SSL_VERIFYPEER
ssl_verify = False

# Modos de cifra fracos
AES/ECB
Cipher.getInstance("AES")
DES
RC4
MD5WithRSA
```

---

## 💣 Auditorias por Categoria

### 1. Hashing Inseguro de Senha

| Algoritmo | Status | Motivo |
|---|---|---|
| `MD5` | 🔴 PROIBIDO | Colisões triviais, rainbow tables públicas |
| `SHA1` | 🔴 PROIBIDO | Colisão demonstrada (SHAttered) |
| `SHA256` sem salt | 🟠 INSEGURO | Sem custo computacional, rainbow tables |
| `SHA256` com salt | 🟡 INADEQUADO | Rápido demais  GPU cracka a 10GB/s |
| `bcrypt` |  SEGURO | Work factor ajustável, salt embutido |
| `argon2id` |  PREFERIDO | Vencedor do Password Hashing Competition |
| `scrypt` |  SEGURO | Memory-hard, resiste a GPU |
| `pbkdf2` |  ACEITÁVEL | Seguro com iterações altas (>600k) |

```python
#  VULNERÁVEL
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()
hashed = hashlib.sha256(password.encode()).hexdigest()

#  CORRETO  bcrypt
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
is_valid = bcrypt.checkpw(password.encode(), hashed)

#  CORRETO  argon2id
from argon2 import PasswordHasher
ph = PasswordHasher()
hashed = ph.hash(password)
ph.verify(hashed, password)
```

---

### 2. Segredos Hardcoded

```python
#  CRÍTICO  segredo no código (versionado no git)
SECRET_KEY = "super_secret_dev_key_123"
DB_PASSWORD = "admin123"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

**Impacto:** qualquer pessoa com acesso ao repositório (incluindo ex-funcionários, contribuidores, vazamentos) tem o segredo. Segredos em git nunca morrem  ficam no histórico mesmo após remoção.

```python
#  CORRETO  variáveis de ambiente
import os
SECRET_KEY = os.environ['SECRET_KEY']
DB_PASSWORD = os.environ['DATABASE_PASSWORD']
```

**Ferramentas de detecção:**
- `git secret` / `detect-secrets` / `gitleaks`
- `git log -p | grep -i password`

---

### 3. Aleatoriedade Insegura em Contexto Crítico

```python
#  VULNERÁVEL  random.random() é determinístico (seedado)
import random
token = str(random.random())            # predizível
reset_token = random.randint(0, 999999) # brute-forçável em minutos
csrf_token = hex(random.getrandbits(32)) # inseguro

#  CORRETO  CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
import secrets
token = secrets.token_hex(32)           # 256 bits de entropia real
reset_token = secrets.token_urlsafe(32) # URL-safe
csrf_token = secrets.token_bytes(32)
```

```javascript
//  VULNERÁVEL
const token = Math.random().toString(36);

//  CORRETO  Node.js
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
```

```java
//  VULNERÁVEL
Random r = new Random();
int token = r.nextInt();

//  CORRETO
SecureRandom sr = new SecureRandom();
byte[] token = new byte[32];
sr.nextBytes(token);
```

---

### 4. Modos de Cifra Fracos

#### ECB (Electronic Code Book)  Padrão Preservado

```python
#  VULNERÁVEL  ECB revela padrões nos dados
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)

#  CORRETO  GCM (autenticado + não-determinístico)
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
nonce = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
```

**Vulnerabilidade visual do ECB:**
> Imagine criptografar uma imagem bitmap com ECB vs GCM.  
> Com ECB, o pinguim do Tux Linux é **visível** mesmo criptografado  os blocos idênticos produzem ciphertext idêntico.

#### IV/Nonce Reutilizado em CBC/GCM

```python
#  VULNERÁVEL  IV fixo = cifra determinística
FIXED_IV = b'\x00' * 16
cipher = AES.new(key, AES.MODE_CBC, FIXED_IV)  # NUNCA reutilizar IV

#  CORRETO  IV aleatório por operação
iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
# Enviar iv concatenado com ciphertext
```

---

### 5. TLS/SSL Desabilitado

```python
#  CRÍTICO  MitM trivial
import requests
r = requests.get('https://api.target.com', verify=False)

#  CRÍTICO  Python urllib
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE  # verifica nada
```

```javascript
//  CRÍTICO  Node.js
const https = require('https');
const agent = new https.Agent({ rejectUnauthorized: false });
```

---

### 6. Chaves de Curto Comprimento

| Algoritmo | Comprimento Mínimo Seguro |
|---|---|
| RSA | 2048 bits (preferir 4096) |
| ECDSA | 256 bits (P-256) |
| AES | 128 bits mínimo (preferir 256) |
| DH Key | 2048 bits |

```
DES (56 bits)  QUEBRADO em horas
3DES  QUEBRADO (SWEET32 attack  CVE-2016-2183)
RSA-1024  INSEGURO (quebrável por estados-nação)
```

---

## 🔗 Chain Exploits

```
MD5 de senha + vazamento do banco  Quebra instantânea via rainbow table
Segredo hardcoded + github público  Comprometimento imediato sem invasão
TLS desabilitado + rede pública  MitM com interceptação de credenciais
Math.random() em token de reset  Brute force do token  Account takeover
ECB mode + dados previsíveis  Inferência do conteúdo sem quebrar a chave
```

---

## 📌 Referências
- [[hashing-inseguro-de-senhas]]
- [[jwt-algorithm-confusion-ataques]]
- [[autenticacao-gestao-de-sessao]]
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
