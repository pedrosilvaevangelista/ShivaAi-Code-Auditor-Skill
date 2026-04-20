# Authentication & Session Management

**Tags:** #high #authentication #session #bruteforce #account-takeover
**OWASP:** A07:2021 Identification and Authentication Failures
**CVSS Base:** 7.5 (High) → 9.8 (Critical → complete bypass)

---

## 📖 What is it

Authentication failures allow an attacker to assume another user's identity — often without needing their password. This includes everything from direct bypass to indirect password reset attacks.

---

## 🔍 `grep_search` Tactics

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

## 💣 Vulnerabilities by Category

### 1. Session Fixation

**How it works:** The server does not regenerate the Session ID after login. The attacker forces the victim to use a pre-defined Session ID; authentication occurs and both share the authenticated session.

```php
//  VULNERABLE — Session ID is not regenerated after login
session_start();
if (login_valid($user, $pass)) {
    $_SESSION['user'] = $user;
    // session ID remains the same as before login
}

//  CORRECT — regenerate Session ID after authentication
session_start();
if (login_valid($user, $pass)) {
    session_regenerate_id(true);  // true = deletes the old session
    $_SESSION['user'] = $user;
}
```

```javascript
//  Correct — Express
req.session.regenerate((err) => {
    req.session.user = user;
    res.redirect('/dashboard');
});
```

### 1.5. Session Donation
**How it works:** Inverse of Fixation. The attacker creates a legitimate session and "donates" it to the victim (via XSS or link). If the victim performs actions (like adding a credit card) while using the attacker's session, the attacker can then use their own session to see the victim's data.

---

### Password Reset — Host Header Injection
**How it works:** The app generates reset links using the `Host` header from the request.
**Attack:**
1. Attacker sends a reset request for victim's email.
2. Attacker sets `Host: attacker.com` in the request header.
3. The server sends the email to the victim with a link like `http://attacker.com/reset?token=...`.
4. If victim clicks, the token is leaked to the attacker's logs.

**Grepping for risk:** `request.get_host()`, `$_SERVER['HTTP_HOST']`.
---

### 2. Logout Without Server-Side Session Invalidation

```javascript
//  VULNERABLE — only deletes the cookie on the client
app.post('/logout', (req, res) => {
    res.clearCookie('session');  // cookie deleted, but server-side session is still valid
    res.redirect('/login');
});

//  CORRECT — destroy the session on the server
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        res.clearCookie('session');
        res.redirect('/login');
    });
});
```

**Impact:** a stolen JWT token still works even after "logout". A session cookie intercepted via XSS remains valid.

---

### 3. Exploitable Password Reset

#### Predictable Reset Token
```python
#  VULNERABLE — timestamp-based (predictable)
import time, hashlib
token = hashlib.md5(str(time.time()).encode()).hexdigest()

#  VULNERABLE — user_id-based (enumerable)
token = hashlib.sha256(f"{user_id}_{email}".encode()).hexdigest()

#  CORRECT — CSPRNG
import secrets
token = secrets.token_urlsafe(32)  # 256 bits of entropy
```

#### Token Without Expiration
```python
#  VULNERABLE — token never expires
PasswordResetToken.objects.create(user=user, token=token)

#  CORRECT — expires in 1 hour
from datetime import datetime, timedelta, timezone
expires = datetime.now(timezone.utc) + timedelta(hours=1)
PasswordResetToken.objects.create(user=user, token=token, expires_at=expires)
```

#### Reusable Token
```python
#  VULNERABLE — token can be used multiple times
def reset_password(token, new_password):
    token_obj = PasswordResetToken.objects.get(token=token)
    token_obj.user.set_password(new_password)
    # token_obj.delete()  — MISSING invalidation!

#  CORRECT
def reset_password(token, new_password):
    token_obj = PasswordResetToken.objects.get(token=token, expires_at__gt=now())
    token_obj.user.set_password(new_password)
    token_obj.delete()  # invalidate after use
```

---

### 4. User Enumeration

```python
#  VULNERABLE — different messages reveal whether emails are registered
@app.post('/login')
def login():
    user = User.query.filter_by(email=email).first()
    if not user:
        return "Email not registered", 401     #  reveals that email does not exist
    if not bcrypt.check_password_hash(user.password, password):
        return "Incorrect password", 401       #  reveals that email exists

#  CORRECT — generic message
@app.post('/login')
def login():
    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return "Invalid credentials", 401      #  same message for both cases
```

**Enumeration via timing:**
> `bcrypt.check_password_hash()` is only called if the user exists → different response time.
> Mitigation: always call bcrypt even when the user does not exist.

```python
#  Timing mitigation
DUMMY_HASH = bcrypt.generate_password_hash("dummy").decode('utf-8')
user = User.query.filter_by(email=email).first()
hash_to_check = user.password if user else DUMMY_HASH
is_valid = bcrypt.check_password_hash(hash_to_check, password)
if not user or not is_valid:
    return "Invalid credentials", 401
```

---

### 5. Absence of Rate Limiting

```python
#  VULNERABLE — free brute force
@app.post('/login')
def login():
    # Without rate limiting, attacker can try 1M passwords/hour
    ...

#  CORRECT — Flask-Limiter
from flask_limiter import Limiter
limiter = Limiter(app, key_func=get_remote_address)

@app.post('/login')
@limiter.limit("5 per minute")  # 5 attempts per minute per IP
def login():
    ...
```

**Critical endpoints that MUST have rate limiting:**
- `POST /login`
- `POST /forgot-password`
- `POST /reset-password`
- `POST /2fa/verify`
- `POST /api/auth/*`

---

### 6. Cookies Without Security Flags

```python
#  VULNERABLE — exposed session cookie
response.set_cookie('session', session_id)
# No HttpOnly → JavaScript can read it (XSS steals the cookie)
# No Secure → sent over HTTP (MitM captures it)
# No SameSite → CSRF possible

#  CORRECT
response.set_cookie(
    'session',
    session_id,
    httponly=True,              # JavaScript cannot access
    secure=True,                # HTTPS required
    samesite='Strict',          # CSRF protection
    max_age=3600,               # expires in 1h
    path='/'
)
```

| Flag | Protects against |
|---|---|
| `HttpOnly` | XSS stealing the cookie via `document.cookie` |
| `Secure` | Interception over HTTP / MitM |
| `SameSite=Strict` | CSRF (cross-origin requests do not send the cookie) |
| `SameSite=Lax` | CSRF (only top-level GET requests pass through) |
| `Max-Age` | Sessions that never expire |

---

## 🔗 Chain Exploits

```
User enumeration + publicly leaked email list → credential stuffing
Predictable reset token → account takeover without victim interaction
Non-invalidated session + XSS → permanent session hijacking
No rate limit on /login + common password list → successful brute force
Cookie without SameSite + privileged POST action → CSRF attack
Session Fixation + link sent by email → automatic session hijacking via `req.session.id` manipulation.
```

### [NEW] Shadow API Endpoints
**How it works:** Undocumented routes (e.g., `/api/debug/v1`, `/internal/status`) that do not share the same authentication middleware as official routes.
**Detection:** Run `grep -r "app.all" .` or search for routes lacking `@login_required` decorators.

---

## 📌 References
- [[jwt-algorithm-confusion-attacks]]
- [[xss-cross-site-scripting]]
- [[csrf-websocket-hijacking-cswsh]]
- [[systemic-cryptography-flaws]]
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)