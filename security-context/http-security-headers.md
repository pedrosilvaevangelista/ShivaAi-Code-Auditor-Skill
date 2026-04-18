# HTTP Security Headers

**Tags:** #medio #headers #csp #hsts #seguranca-browser
**OWASP:** A05:2021  Security Misconfiguration
**CVSS Base:** 0.0 (Info isolado)  amplificador de outras vulnerabilidades

---

## 📖 O que é

HTTP Security Headers não são vulnerabilidades por si só, mas **amplificadores de impacto**  sua ausência torna outras vulnerabilidades (XSS, Clickjacking, MitM) muito mais graves. Reclassificar findings adjacentes quando headers críticos estão ausentes.

---

## 🔍 `grep_search` Táticas

```
helmet(
helmet.contentSecurityPolicy
app.use(helmet
res.setHeader
add_header
Content-Security-Policy
Strict-Transport-Security
X-Frame-Options
X-Content-Type-Options
Referrer-Policy
Permissions-Policy
```

---

## 📊 Matriz de Headers Obrigatórios

| Header | Valor Recomendado | Ausência Permite |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'` + whitelist | XSS sem restrição, injeção de scripts externos |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Downgrade para HTTP, MitM |
| `X-Frame-Options` | `DENY` ou `SAMEORIGIN` | Clickjacking, UI redressing, iframe embedding |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing  XSS via arquivo upload |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Tokens/paths sensíveis vazam no Referer |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Acesso indevido a hardware do usuário |
| `Cache-Control` | `no-store` (em rotas privadas) | Dados sensíveis cacheados no browser |
| `Cross-Origin-Opener-Policy` | `same-origin` | Side-channel attacks (Spectre) |
| `Cross-Origin-Resource-Policy` | `same-origin` | Cross-origin data leaks |

---

## 🔑 Content-Security-Policy (CSP)  Deep Dive

### Diretivas Essenciais

```
default-src 'self'           Apenas recursos do próprio domínio
script-src 'self'            Scripts apenas do domínio próprio
script-src 'nonce-{NONCE}'   Somente scripts com nonce dinâmico
object-src 'none'            Bloquear Flash/plugins
base-uri 'self'              Prevenir injeção de <base>
frame-ancestors 'none'       Bloquear embedding em iframe (= X-Frame-Options: DENY)
upgrade-insecure-requests    Forçar HTTPS em recursos embutidos
```

### Exemplos por Ambiente

```
# Modo estrito (preferível)
Content-Security-Policy: default-src 'none'; script-src 'self' 'nonce-{RANDOM}'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self';

# Modo moderado (prático)
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self';

# Modo report-only (não bloqueia, apenas reporta)
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-violations
```

### Bypasses de CSP Mal Configurado

```
# wildcard excessivo
Content-Security-Policy: script-src *    inútil

# unsafe-inline (anula proteção de XSS)
Content-Security-Policy: script-src 'self' 'unsafe-inline'

# unsafe-eval (permite eval())
Content-Security-Policy: script-src 'self' 'unsafe-eval'

# allow-list com CDN inseguro
Content-Security-Policy: script-src 'self' cdn.example.com
# Se cdn.example.com tiver JSONP endpoint  bypass via JSONP
```

---

## 🔑 HSTS  HTTP Strict Transport Security

```
# Mínimo seguro
Strict-Transport-Security: max-age=31536000

# Máximo seguro (com subdomínios e preload)
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Sem HSTS:**
- Primeira visita pode ser interceptada (se o usuário digita `http://...`)
- SSL stripping attack: atacante remove HTTPS de todas as respostas
- Downgrade MitM: sessão completa em cleartext

---

## 🔑 X-Frame-Options

```
X-Frame-Options: DENY                nunca pode ser embedded (preferível)
X-Frame-Options: SAMEORIGIN          somente iframes do mesmo domínio
X-Frame-Options: ALLOW-FROM https://trusted.com   deprecado
```

**Sem X-Frame-Options:**
- Clickjacking: atacante embute sua app em iframe invisível e capta cliques do usuário
- UI Redressing: capturar credenciais via input sobreposto
- Drag-and-drop data exfiltration

---

## ️ Implementação por Framework

### Express.js  Helmet

```javascript
//  CORRETO  Helmet com configuração explícita
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));
```

### Django

```python
# settings.py   CORRETO
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
X_FRAME_OPTIONS = 'DENY'
SECURE_SSL_REDIRECT = True

CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_OBJECT_SRC = ("'none'",)
CSP_FRAME_ANCESTORS = ("'none'",)
```

### Flask

```python
from flask_talisman import Talisman

Talisman(app,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'object-src': "'none'",
    },
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    x_frame_options='DENY',
    referrer_policy='strict-origin-when-cross-origin'
)
```

### NGINX

```nginx
#  CORRETO  nginx.conf
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';" always;
```

---

## 🔗 Chain Exploits (Reclassificações por Ausência de Header)

```
XSS Stored 🟡 + Sem CSP  🟠 Alto (script arbitrário sem restrição)
XSS Reflected 🔵 + Sem CSP  🟡 Médio  🟠 Alto
Sem HSTS  Primeiro acesso em HTTP  Credentials interceptadas (MitM)  🟠 Alto
Sem X-Frame-Options  Clickjacking em formulário de pagamento  🟠 Alto
MIME sniffing + upload de SVG  XSS via Content-Type equivocado  🟡 Médio
```

---

## 🛠️ Ferramenta de Verificação

```python
# .tmp/check_headers.py
import requests

TARGET = "http://target.com"

REQUIRED_HEADERS = {
    "Content-Security-Policy": "🔴 Protege contra XSS",
    "Strict-Transport-Security": "🟠 Protege contra MitM/downgrade",
    "X-Frame-Options": "🟡 Protege contra Clickjacking",
    "X-Content-Type-Options": "🟡 Protege contra MIME sniffing",
    "Referrer-Policy": "🔵 Evita vazar tokens em Referer",
    "Permissions-Policy": "🔵 Controla acesso a hardware",
}

r = requests.get(TARGET, verify=False, timeout=10)
headers = {k.lower(): v for k, v in r.headers.items()}

print(f"=== HTTP Security Headers  {TARGET} ===\n")
for header, description in REQUIRED_HEADERS.items():
    value = headers.get(header.lower())
    if value:
        print(f"  {header}: {value[:80]}")
    else:
        print(f"  {header} AUSENTE  {description}")
```

---

## 📌 Referências
- [[xss-cross-site-scripting]]
- [[csrf-websocket-hijacking-cswsh]]
- [[chain-exploit-efeito-borboleta]]
- [SecurityHeaders.com](https://securityheaders.com/)
- [MDN CSP Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
