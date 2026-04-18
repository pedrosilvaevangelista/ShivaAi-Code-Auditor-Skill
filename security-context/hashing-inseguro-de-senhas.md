# Hashing Inseguro de Senhas

**Tags:** #alto #hashing #senha #rainbow-table #brute-force
**OWASP:** A02:2021  Cryptographic Failures
**CVSS Base:** 7.5 (Alto  credenciais quebráveis em minutos com GPU)

---

## 📖 O que é

A escolha do algoritmo de hashing de senha define a resistência do sistema a um atacante que obtém o banco de dados. Algoritmos rápidos (MD5, SHA-1, SHA-256) são quebráveis em GPU a bilhões de tentativas por segundo. Algoritmos de senha corretos adicionam custo computacional deliberado.

---

## 📊 Tabela de Algoritmos

| Algoritmo | Status | Velocidade (GPU) | Resistência |
|---|---|---|---|
| MD5 | 🔴 PROIBIDO | ~200 GB/s | Nenhuma |
| SHA-1 | 🔴 PROIBIDO | ~100 GB/s | Nenhuma |
| SHA-256 sem salt | 🔴 PROIBIDO | ~10 GB/s | Rainbow tables: 0 |
| SHA-256 com salt | 🟠 INSUFICIENTE | ~10 GB/s | Brute force ainda trivial |
| MD5-crypt ($1$) | 🟠 INSUFICIENTE | ~500 MH/s | Ultrapassado |
| SHA-512-crypt ($6$) | 🟡 LIMITADO | ~5 MH/s | Apenas para Linux |
| **bcrypt** |  SEGURO | ~184 kH/s | Work factor ajustável |
| **argon2id** |  PREFERIDO | ~800 H/s | Memory+CPU-hard |
| **scrypt** |  SEGURO | ~1 kH/s | Memory-hard |
| **PBKDF2** |  ACEITÁVEL | ~200 kH/s | Aprovado por NIST |

---

## 🔍 `grep_search` Táticas

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

## 💣 Padrões Vulneráveis

### Python

```python
#  VULNERÁVEL  MD5 sem salt
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()

#  VULNERÁVEL  SHA256 sem salt (rainbow table)
hashed = hashlib.sha256(password.encode()).hexdigest()

#  VULNERÁVEL  SHA256 com salt mas sem custo
salt = os.urandom(16)
hashed = hashlib.sha256(salt + password.encode()).hexdigest()
#  Quebrável em minutos com GPU
```

### PHP

```php
//  VULNERÁVEL  MD5
$hash = md5($password);  // quebrável em ms

//  VULNERÁVEL  SHA1
$hash = sha1($password);

//  VULNERÁVEL  MD5 com salt manual (ainda rápido)
$hash = md5($salt . $password);
```

### Java

```java
//  VULNERÁVEL
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes());

//  VULNERÁVEL  SHA-1
MessageDigest sha = MessageDigest.getInstance("SHA-1");
```

### JavaScript / Node.js

```javascript
//  VULNERÁVEL
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');
const hash2 = crypto.createHash('sha256').update(password).digest('hex');
```

---

##  Implementações Corretas

### Python  bcrypt (preferido para simplicidade)

```python
#  CORRETO
import bcrypt

def hash_password(password: str) -> str:
    # gensalt(rounds=12)  work factor padrão (2^12 iterações)
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
```

### Python  argon2id (melhor escolha moderna)

```python
#  CORRETO  argon2-cffi
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(
    time_cost=2,        # número de iterações
    memory_cost=65536,  # 64 MB de memória
    parallelism=2,      # threads paralelas
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
//  CORRETO  password_hash com bcrypt
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

//  CORRETO  password_hash com argon2id (PHP 7.3+)
$hash = password_hash($password, PASSWORD_ARGON2ID);

// Verificar
if (password_verify($input_password, $stored_hash)) {
    // autenticado
}
```

### Java  Spring Security

```java
//  CORRETO  BCryptPasswordEncoder
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);  // strength=12
String hashed = encoder.encode(rawPassword);
boolean matches = encoder.matches(rawPassword, hashed);
```

### Node.js

```javascript
//  CORRETO  bcrypt
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

## 🧪 Script de Análise de Hash

```python
# .tmp/analyze_hash.py  Identificar tipos de hash no banco
# DESCARTAR APÓS USO

import re, sys

def identify_hash(hash_str: str) -> str:
    """Identifica o tipo de hash pelo formato."""
    if hash_str.startswith('$2b$') or hash_str.startswith('$2a$') or hash_str.startswith('$2y$'):
        cost = int(hash_str.split('$')[2])
        return f"bcrypt (cost={cost}) {' SEGURO' if cost >= 10 else '️ CUSTO BAIXO'}"
    elif hash_str.startswith('$argon2id$'):
        return "argon2id  SEGURO"
    elif hash_str.startswith('$argon2i$') or hash_str.startswith('$argon2d$'):
        return "argon2 (não-id) ️ USAR argon2id"
    elif hash_str.startswith('$6$'):
        return "SHA-512-crypt (Linux) 🟡 OK mas não ideal"
    elif hash_str.startswith('$1$'):
        return "MD5-crypt 🔴 INSEGURO"
    elif re.match(r'^[0-9a-f]{32}$', hash_str):
        return "MD5 (sem salt) 🔴 CRÍTICO"
    elif re.match(r'^[0-9a-f]{40}$', hash_str):
        return "SHA-1 🔴 INSEGURO"
    elif re.match(r'^[0-9a-f]{64}$', hash_str):
        return "SHA-256 🟠 RÁPIDO DEMAIS para senha"
    elif re.match(r'^[0-9a-f]{128}$', hash_str):
        return "SHA-512 🟠 RÁPIDO DEMAIS para senha"
    else:
        return "Desconhecido  verificar manualmente"

# Exemplos
test_hashes = [
    "5f4dcc3b5aa765d61d8327deb882cf99",  # MD5 de "password"
    "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8JBIXIJDWMQR7NwDvS",  # bcrypt
    "$argon2id$v=19$m=65536,t=2,p=2$...",
]

for h in test_hashes:
    print(f"{h[:30]}...  {identify_hash(h)}")
```

---

## 🔗 Chain Exploits

```
MD5/SHA1 de senha + vazamento de banco  Quebra em minutos com hashcat + GPU
SHA256 sem salt + banco público  Rainbow table lookup instantâneo
Bcrypt com custo baixo (< 10)  Brute force acelerado
Hash idêntico para mesma senha  Usuários que usam mesma senha são detectáveis
Senha no log de erro  Comprometimento direto sem quebra de hash
```

---

## 📌 Referências
- [[criptografia-falhas-sistematicas]]
- [[autenticacao-gestao-de-sessao]]
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
