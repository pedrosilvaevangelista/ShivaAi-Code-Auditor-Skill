# Cognitive Taint Analysis

**Tags:** #methodology #taint-analysis #tracking #vulnerability-detection
**Type:** Cognitive protocol — *not a vulnerability*

---

## 📖 Definition

Cognitive Taint Analysis is the process of tracking the flow of untrusted data (Taint) from the **Source** (user input) to a **Sink** (dangerous function where execution/persistence occurs).

The engine must mentally trace the "chain of custody" of the data, identifying where sanitization is missing or insufficient.

---

## 🛠️ The 5-Step Protocol

```markdown
1. IDENTIFY: What feeds this sink?
    Trace upwards: where does the variable passed to the sink come from?

2. TRACE: Path-walk back to the Source
    Examine each intermediate function: where does this variable come from?
    Map: req.body.X -> sanitizeInput(X) -> buildQuery(X) -> exec(query)

3. EVALUATE: Is there real sanitization in the path?
    Explicit Whitelist? (Reliable)
    Blacklist? (Unreliable — likely bypassable)
    Parameterization? (Reliable for SQLi)
    Encoding? (May not be sufficient depending on the context)

4. CONFIRM: Does sanitization occur in the correct context?
    Sanitization for XSS does not protect against SQLi.
    escapeshellarg() does not protect against SQLi.
    htmlspecialchars() does not protect against shell execution.

5. ANCHOR: Document the exact file + line for each point in the chain.
```

---

## 📊 Data Flow Micro-Graph

When analyzing each file, mentally record:

```text
File: routes/user.js

INPUT:    req.body.username -> route POST /login
PASSES:   controllers/auth.js -> authenticateUser(username, password)
ARRIVES:  models/User.js -> db.query(`SELECT * WHERE name='${username}'`)
SINK:     db.query() with direct concatenation -> SQLi CONFIRMED

EVIDENCE: routes/user.js:42 | controllers/auth.js:78 | models/User.js:23
```

---

## 🔍 Cross-File Correlation

For large projects, use `grep_search` **by specific variable** to trace the taint cross-file:

```powershell
# Trace where 'username' is used after entry
# Grep for all usages of the variable in the entire project
grep_search --SearchPath "." --Query "username"

# Trace the function that processes the data
# Then grep by the specific function to see where it is called
grep_search --SearchPath "." --Query "authenticateUser"
```

---

## 📌 References
- [[eip-exploratory-investigation-protocol]]
- [[second-order-injection]]
- [[sql-injection-sqli]]
- [[command-injection-rce]]
