# Autenticação & Gestão de Sessão

**Tags:** #alto #autenticacao #sessao #bruteforce #account-takeover
**OWASP:** A07:2021 — Identification and Authentication Failures
**CVSS Base:** 7.5 (Alto) → 9.8 (Crítico — bypass completo)

---

## 📖 O que é

Falhas de autenticação permitem ao atacante assumir a identidade de outro usuário — frequentemente sem precisar da senha. Inclui desde bypass direto até ataques indiretos de reset de senha.

---

## 🔍 `grep_search` Táticas

```
session_regenerate_id()
req.session.regenerate
session.regenerate
Set-Cookie
HttpOnly
Secure
SameSite
rate-limit
throttle
ratelimit
reset_password
forgot_password
token.*expire
bcrypt
password_hash
compare
```

---

## 💣 Vulnerabilidades por Categoria

### 1. Session Fixation

**Como funciona:** O servidor não regenera o Session ID após o login. O atacante força a vítima a usar um Session ID pré-definido, atenticação ocorre, ambos compartilham a sessão autenticada.

```php
// ❌ VULNERÁVEL — Session ID não é regenerado após login
session_start();
if (login_valid($user, $pass)) {
    $_SESSION['user'] = $user;
    // session ID permanece o mesmo de antes do login
}

// ✅ CORRETO — regenerar Session ID após autenticação
session_start();
if (login_valid($user, $pass)) {
    session_regenerate_id(true);  // true = apaga a sessão antiga
    $_SESSION['user'] = $user;
}
```

```javascript
// ✅ Correto — Express
req.session.regenerate((err) => {
    req.session.user = user;
    res.redirect('/dashboard');
});
```

---

### 2. Logout sem Invalidação de Sessão Server-Side

```javascript
// ❌ VULNERÁVEL — somente apaga o cookie no cliente
app.post('/logout', (req, res) => {
    res.clearCookie('session');  // cookie deletado, mas sessão no servidor ainda válida
    res.redirect('/login');
});

// ✅ CORRETO — destruir a sessão no servidor
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        res.clearCookie('session');
        res.redirect('/login');
    });
});
```

**Impacto:** um token JWT roubado ainda funciona mesmo após "logout". Um cookie de sessão interceptado por XSS permanece válido.

---

### 3. Reset de Senha Explorável

#### Token de Reset Previsível
```python
# ❌ VULNERÁVEL — baseado em timestamp (previsível)
import time, hashlib
token = hashlib.md5(str(time.time()).encode()).hexdigest()

# ❌ VULNERÁVEL — baseado em user_id (enumerável)
token = hashlib.sha256(f"{user_id}_{email}".encode()).hexdigest()

# ✅ CORRETO — CSPRNG
import secrets
token = secrets.token_urlsafe(32)  # 256 bits de entropia
```

#### Token sem Expiração
```python
# ❌ VULNERÁVEL — token nunca expira
PasswordResetToken.objects.create(user=user, token=token)

# ✅ CORRETO — expira em 1 hora
from datetime import datetime, timedelta, timezone
expires = datetime.now(timezone.utc) + timedelta(hours=1)
PasswordResetToken.objects.create(user=user, token=token, expires_at=expires)
```

#### Token Reutilizável
```python
# ❌ VULNERÁVEL — token pode ser usado múltiplas vezes
def reset_password(token, new_password):
    token_obj = PasswordResetToken.objects.get(token=token)
    token_obj.user.set_password(new_password)
    # token_obj.delete()  ← FALTOU invalidar!

# ✅ CORRETO
def reset_password(token, new_password):
    token_obj = PasswordResetToken.objects.get(token=token, expires_at__gt=now())
    token_obj.user.set_password(new_password)
    token_obj.delete()  # invalidar após uso
```

---

### 4. Enumeração de Usuários

```python
# ❌ VULNERÁVEL — mensagens diferentes expõem validade de emails
@app.post('/login')
def login():
    user = User.query.filter_by(email=email).first()
    if not user:
        return "Email não cadastrado", 401     # ← revela que email não existe
    if not bcrypt.check_password_hash(user.password, password):
        return "Senha incorreta", 401          # ← revela que email existe

# ✅ CORRETO — mensagem genérica
@app.post('/login')
def login():
    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return "Credenciais inválidas", 401    # ← mesma mensagem para ambos os casos
```

**Enumeração por timing:**
> `bcrypt.check_password_hash()` só é chamado se o usuário existe → tempo de resposta diferente.
> Mitigação: sempre chamar bcrypt mesmo quando usuário não existe.

```python
# ✅ Mitigação de timing
DUMMY_HASH = bcrypt.generate_password_hash("dummy").decode('utf-8')
user = User.query.filter_by(email=email).first()
hash_to_check = user.password if user else DUMMY_HASH
is_valid = bcrypt.check_password_hash(hash_to_check, password)
if not user or not is_valid:
    return "Credenciais inválidas", 401
```

---

### 5. Ausência de Rate Limiting

```python
# ❌ VULNERÁVEL — brute force livre
@app.post('/login')
def login():
    # Without rate limiting, attacker can try 1M passwords/hour
    ...

# ✅ CORRETO — Flask-Limiter
from flask_limiter import Limiter
limiter = Limiter(app, key_func=get_remote_address)

@app.post('/login')
@limiter.limit("5 per minute")  # 5 tentativas por minuto por IP
def login():
    ...
```

**Endpoints críticos que DEVEM ter rate limiting:**
- `POST /login`
- `POST /forgot-password`
- `POST /reset-password`
- `POST /2fa/verify`
- `POST /api/auth/*`

---

### 6. Cookies sem Flags de Segurança

```python
# ❌ VULNERÁVEL — cookie de sessão exposto
response.set_cookie('session', session_id)
# Sem HttpOnly → JavaScript pode ler (XSS roba o cookie)
# Sem Secure → enviado em HTTP (MitM captura)
# Sem SameSite → CSRF possível

# ✅ CORRETO
response.set_cookie(
    'session',
    session_id,
    httponly=True,              # JavaScript não acessa
    secure=True,                # HTTPS obrigatório
    samesite='Strict',          # CSRF protection
    max_age=3600,               # expira em 1h
    path='/'
)
```

| Flag | Protege contra |
|---|---|
| `HttpOnly` | XSS roubando o cookie via `document.cookie` |
| `Secure` | Interceptação em HTTP / MitM |
| `SameSite=Strict` | CSRF (requisições cross-origin não enviam o cookie) |
| `SameSite=Lax` | CSRF (somente GET top-level atravessa) |
| `Max-Age` | Sessões que nunca expiram |

---

## 🔗 Chain Exploits

```
Enumeração de usuários + lista pública de emails vazados → credential stuffing
Reset token previsível → account takeover sem interação da vítima
Session não invalidada + XSS → roubo de sessão permanente
Sem rate limit em /login + lista de senhas comuns → brute force bem-sucedido
Cookie sem SameSite + ação privilegiada via POST → CSRF attack
Session Fixation + link enviado por email → sequestro automático de sessão
```

---

## 📌 Referências
- [[JWT — Algorithm Confusion & Ataques]]
- [[XSS — Cross-Site Scripting]]
- [[CSRF & WebSocket Hijacking (CSWSH)]]
- [[Criptografia — Falhas Sistemáticas]]
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
