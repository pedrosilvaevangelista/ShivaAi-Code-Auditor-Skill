# Insecure Deserialization Protocol

**Tags:** #critical #rce #deserialization #python #nodejs #php #java
**OWASP:** A08:2021 Software and Data Integrity Failures
**CVSS Base:** 9.8 (Critical — unauthenticated RCE)

---

## 📖 What it is

Insecure Deserialization occurs when an application takes untrusted serialized data and converts it back into an object without proper validation. This often allows an attacker to manipulate object properties to trigger unintended code paths, eventually leading to Remote Code Execution (RCE).

---

## 🔍 `grep_search` Tactics

```
# Python
pickle.loads
yaml.load(          → check if Loader is safe
marshal.loads
shelve.open

# Node.js
node-serialize
serialize-javascript
JSON.parse(         → check for Prototype Pollution

# PHP
unserialize(
phar://

# Java
readObject(
ObjectInputStream
XMLDecoder
```

---

## 💣 Attack Patterns

### 1. Python Pickle RCE
**How it works:** The `pickle` module is inherently insecure. The `__reduce__` method can be overridden to execute systemic commands upon deserialization.

**Payload:**
```python
import pickle, os
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',)) # Any command
```

### 2. PHP Object Injection
**How it works:** Exploiting "Magic Methods" like `__destruct` or `__wakeup` in available classes to create a "Gadget Chain" that leads to file deletion or execution.

### 3. Java Deserialization (Gadget Chains)
**How it works:** Using common libraries in the classpath (e.g., Commons-Collections) to build a complex chain of method calls that execute a command.
**Tool:** `ysoserial` (Payload generation for common chains).

### [NEW] Node.js `node-serialize` RCE
**How it works:** Exploiting the `_$$ND_FUNC$$_` prefix to execute immediate functions during deserialization.
**Payload:** `{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('id').toString()}()"}`

---

## 🛡️ Fix

1. **Never deserialize untrusted data.**
2. **Safe Formats:** Use JSON or XML with strict schema validation.
3. **Signing:** If you must use serialization, sign the data (HMAC) to prevent tampering.
4. **Safe Loaders:** In Python, use `yaml.safe_load()`. In Java, use `ValidatingObjectInputStream`.

---

## 🔗 Chain Exploits

```
Insecure Deserialization + File Write ➔ Remote Command Execution
Deserialization + Shared Library ➔ Gadget Chain ➔ Host Takeover
```
