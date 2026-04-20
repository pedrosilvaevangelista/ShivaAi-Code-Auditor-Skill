# Cognitive Taint Analysis — Elite Operational Protocol

> **Type:** Methodology — the engine's mental framework for translating raw code reading into confirmed vulnerability chains. This is not a vulnerability itself; it is the cognitive protocol that makes the difference between finding a sink and proving an exploit.

**Tags:** #methodology #taint-analysis #sast #data-flow #cross-file-correlation
**Application:** Applied universally — every vulnerability class uses this framework.

---

## Core Axiom

> **A sink without a source is noise. A source without a sink is incomplete. A chain is evidence.**

The goal of taint analysis is to construct an **unbroken evidence chain** from an external input (Source) to a dangerous function (Sink), proving that the attacker controls the data that reaches execution.

---

## The Source → Transform → Sink Model

```
[SOURCE]                [TRANSFORMS]                  [SINK]
─────────               ─────────────────             ──────────────────
req.body.username  →  sanitize(x) → buildQuery(x)  →  db.query(query)
req.query.file     →  path.join(base, x)            →  fs.readFile(path)
req.headers.host   →  url = "https://" + x          →  res.redirect(url)
event.data         →  JSON.parse(x) → merge(obj, x) →  eval(obj.template)
```

**The auditor must:**
1. Find the Sink (dangerous function).
2. Walk backwards to identify what feeds it.
3. Identify every transform applied along the way.
4. Determine if any transform provides a **complete, context-appropriate** sanitization.

---

## The 5-Step Operational Protocol

### Step 1 — SINK FIRST: Start from Danger
Begin with `grep_search` on high-priority sinks:
```
SQL:     query(, db.execute(, $pdo->query(, connection.query(
Shell:   exec(, spawn(, system(, popen(, child_process.exec(
File:    readFile(, include(, open(, sendFile(, file_get_contents(
Dom:     innerHTML =, document.write(, eval(, dangerouslySetInnerHTML
Redirect: res.redirect(, header("Location:", location.href =
Template: render(, template.render(, env.from_string(, Jinja2.Template(
```

**Why sink-first?** It eliminates false starts — only follow a taint chain if a dangerous destination exists.

### Step 2 — TRACE: Walk Backwards to the Source
For each found sink, identify what variable feeds it and trace it upstream:

```javascript
// Example trace from sink to source:
db.query(sqlStr)               // SINK found
  ↑ sqlStr = buildQuery(name)  // transform
    ↑ name = req.body.username // SOURCE — user-controlled
```

**Use `grep_search` to trace** function definitions across files:
```
grep_search → "buildQuery"  → traces to definition in utils/db.js
grep_search → "sanitizeInput" → traces to definition, reveals only HTML encoding (not SQL-safe)
```

### Step 3 — EVALUATE: Qualify All Transforms

Score every transform in the chain:

| Transform Type | Security Verdict | Notes |
|---|---|---|
| Explicit whitelist | ✅ Reliable | Only allows known-safe values |
| Parameterized query | ✅ Reliable | Prevents SQLi specifically |
| `htmlspecialchars()` | ⚠️ Context-dependent | Safe for HTML, NOT for SQL/shell |
| Blacklist filter | ❌ Usually bypassable | Enumerate bypass patterns |
| `.replace('\'', '')` | ❌ Insufficient | Unicode, encoding, multi-char bypasses |
| Type casting (`intval()`) | ✅ If numeric | Forces integer — kills string injection |
| `escapeshellarg()` | ✅ For shell | Only safe for shell, not SQL/template |
| `strip_tags()` | ❌ Insufficient for XSS | Event handlers in attributes survive |

### Step 4 — CONFIRM: Context Mismatch Detection

A transform that is correct for one context is **not portable** to another:

```
htmlspecialchars($x) in HTML → protects against XSS
htmlspecialchars($x) in SQL query → does NOT protect against SQLi (no quotes encoding for SQL)
escapeshellarg($x) for shell → protects against command injection
escapeshellarg($x) in template → meaningless — different execution context
```

**The classic false-positive trap:** Developer encodes for HTML, auditor confirms HTML encoding, both miss the SQLi that uses the same unescaped value in a DB query.

**Protocol:** When you find sanitization, trace *every consumption* of the sanitized value. Multiple consumers often have different contexts.

### Step 5 — ANCHOR: Evidence Documentation Format

Every confirmed vulnerability MUST reference the exact evidence chain:

```
FINDING: SQL Injection — Authenticated
SEVERITY: High

SOURCE:   routes/user.js:42   → req.body.username
PASS:     controllers/auth.js:78 → sanitizeInput(username) [htmlspecialchars only]
SINK:     models/User.js:23   → db.query(`WHERE name='${username}'`)

TRANSFORM VERDICT: htmlspecialchars() applied — ineffective against SQLi context.
No parameterization, no whitelisting.

PoC Payload: username = "' OR '1'='1' --"
```

---

## Cross-File Correlation Protocol

When a variable crosses file or module boundaries, use `grep_search` to follow it:

```
1. Find variable name at sink: `sqlStr`
2. grep_search for "sqlStr" → discovers it's set in utils/queryBuilder.js
3. Read utils/queryBuilder.js → identifies it concatenates req.body.search
4. grep_search for "req.body.search" → confirms no sanitization
5. Evidence chain complete: 3 files, 3 anchors
```

**Multi-Service Taint Protocol (Microservices):**
- Data crossing a message queue (Kafka, RabbitMQ) is still tainted — the queue is not a trust boundary unless cryptographic signing and schema validation are applied.
- Data coming from an internal API endpoint is still tainted unless that endpoint performs its own complete sanitization of the original external input.
- **Never assume data is clean because it came from "internal" sources.**

---

## Anti-Pattern: Sanitization Decoys

The most dangerous false-negative patterns:

### 1. Sanitization at Input, Not at Sink
```python
clean = escape(user_input)  # Sanitized here...
store_in_db(clean)          # ...stored cleanly...
sql = f"SELECT * WHERE x='{fetch_from_db()}'  # ...but re-used without sanitization here
```

### 2. Sanitization for Wrong Context
```php
$username = htmlspecialchars($_POST['username']); // HTML-safe
$query = "SELECT * FROM users WHERE username = '$username'"; // NOT SQL-safe
```

### 3. Sanitization on One Branch Only
```javascript
if (isAdmin) {
    username = sanitize(req.body.username);
} else {
    username = req.body.username; // No sanitization on non-admin path
}
db.query(`SELECT * WHERE user='${username}'`); // Both paths reach this sink
```

---

## Taint Flow Templates by Vulnerability Class

| Class | Source | Transform to Verify | Sink |
|---|---|---|---|
| SQLi | `req.body.*`, `req.query.*` | Parameterization | `db.query(`, `execute(` |
| XSS | `req.body.*`, DB reads | HTML encoding (whitespace attribute ctx) | `innerHTML`, `render(`, `document.write(` |
| SSTI | Template fields, DB reads | Template escaping | `Jinja2.Template(`, `render(`, `env.from_string(` |
| RCE | Any | `escapeshellarg()` on all args | `exec(`, `spawn(`, `system(` |
| SSRF | URL parameters | URL scheme + host whitelist | `fetch(`, `axios.get(`, `curl_exec(` |
| Path Traversal | Filename params | `realpath()` + prefix check | `readFile(`, `sendFile(`, `open(` |
| Open Redirect | Return URL params | Whitelist of allowed domains | `res.redirect(`, `Location:` header |

---

## Strategic Meta-Rules for the Engine

1. **Never declare a sink "safe" without reading the sanitization function's source code.**
2. **Follow every variable across file boundaries using `grep_search` before concluding it is safe.**
3. **A blacklist filter is never a definitive fix — document the bypass potential regardless.**
4. **One sanitization function applied to a variable doesn't sanitize all uses — trace each consumer independently.**

---

*Tags: #methodology #taint-analysis #data-flow #evidence-chain #source-to-sink #cognitive-protocol #shiva-vault*
