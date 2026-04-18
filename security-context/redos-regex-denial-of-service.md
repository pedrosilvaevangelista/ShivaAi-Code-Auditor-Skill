# ReDoS  Regex Denial of Service

**Tags:** #medio #redos #dos #regex #node
**OWASP:** A04:2021  Insecure Design
**CVSS Base:** 6.5 (Médio)  DoS via thread blocking

---

## 📖 O que é

ReDoS (Regular Expression Denial of Service) ocorre quando um padrão de regex com **backtracking catastrófico** processa inputs controlados pelo atacante. Um input de 50 caracteres pode travar 100% de uma thread Node.js por segundos  efetivo DoS. JavaScript é single-threaded, tornando isso especialmente devastador.

---

## 🔍 `grep_search` Táticas

```
new RegExp(userInput
RegExp(req.
new RegExp(req.
test(
match(
exec(
replace(
```

**Verificar também:** regex estáticas com quantificadores aninhados (não dependem de input externo, mas qualquer input válido pode atingir):

```
([a-zA-Z]+)*
(a+)+
(a|aa)+
(.*)*
(\d+)+
```

---

## 💣 Padrões de Regex Vulneráveis (Backtracking Catastrófico)

| Padrão | Risco |
|---|---|
| `(a+)+` | Catastrófico para `"aaaaaaaab"` |
| `([a-zA-Z]+)*` | Catastrófico para `"aaaaaaaa!"` |
| `(a\|aa)+$` | Catastrófico |
| `(.+\s?)*` | Catastrófico |
| `(w+\s?)+` | Catastrófico em validação de emaill |
| `^(([a-z]+B)+\|A)*$` | Catastrófico |

---

## 💣 Exemplos de Código Vulnerável

### Regex Construída com Input do Usuário

```javascript
//  VULNERÁVEL  aplicar regex do usuário sobre dados
app.post('/search', (req, res) => {
    const pattern = req.body.pattern;
    const data = getAllData();
    
    // Regex construída com input do usuário!
    const regex = new RegExp(pattern, 'g');
    const results = data.filter(item => regex.test(item));
    res.json(results);
});

// Exploit: pattern = "(.*)*a" com string longa  trava o processo
```

### Regex Estática com Backtracking

```javascript
//  VULNERÁVEL  regex com quantificadores aninhados
function validateEmail(email) {
    // Padrão vulnerável ao ReDoS
    const emailRegex = /^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$/;
    return emailRegex.test(email);
}

// Exploit: "aaaaaaaaaaaaaaaaaaaaaaaaaaa@"  catastrófico
```

---

## 🧪 Script de Validação de ReDoS

```python
# .tmp/validate_redos.py
import re, time

# Padrões a testar
PATTERNS_TO_TEST = [
    r'([a-zA-Z]+)*',
    r'(a+)+',
    r'(a|aa)+',
    r'(\w+\s?)+',
    r'^(([a-z]+B)+|A)*$',
]

# Inputs que causam backtracking catastrófico
def generate_evil_input(base_char='a', length=30):
    return base_char * length + 'X'  # X no final força backtracking

print("=== ReDoS Vulnerability Test ===\n")

for pattern in PATTERNS_TO_TEST:
    evil_input = generate_evil_input(length=30)
    
    start = time.time()
    try:
        result = re.search(pattern, evil_input, timeout=3)  # timeout para não travar
        elapsed = time.time() - start
        
        if elapsed > 1.0:
            print(f"[🔴 VULN - {elapsed:.2f}s] ReDoS: /{pattern}/")
            print(f"  Input malicioso: {evil_input[:50]}")
        else:
            print(f"[ok - {elapsed:.4f}s] /{pattern}/")
    except re.error:
        print(f"[invalid] /{pattern}/ erro na compilação")
    except TimeoutError:
        elapsed = time.time() - start
        print(f"[🔴 VULN - TIMEOUT {elapsed:.2f}s] ReDoS: /{pattern}/")
```

---

## 🛡️ Correção

### 1. Nunca Construir Regex com Input do Usuário

```javascript
//  CORRETO  busca por string exata em vez de regex
app.post('/search', (req, res) => {
    const searchTerm = req.body.query;
    
    // Busca literal, não regex
    const results = data.filter(item => 
        item.toLowerCase().includes(searchTerm.toLowerCase())
    );
    res.json(results);
});
```

### 2. Usar Regex sem Backtracking (Possessive Quantifiers / Atomic Groups)

```javascript
// Se regex é necessária com input do usuário:
// Substituir regex por validação de input primeiro

function safeSearch(userPattern, data) {
    // Verificar se o padrão tem construções perigosas
    const dangerousPatterns = [
        /(\|)+\+/,  // OR groups quantificados
        /\([^)]+\)\+/,  // grupos com +
        /\([^)]+\)\*/,  // grupos com *
    ];
    
    for (const danger of dangerousPatterns) {
        if (danger.test(userPattern)) {
            throw new Error("Padrão de regex perigoso rejeitado");
        }
    }
    
    const regex = new RegExp(userPattern);
    return data.filter(item => regex.test(item));
}
```

### 3. Bibliotecas de Regex "Safe" (RE2)

```javascript
//  RE2  implementação sem backtracking catastrófico
const RE2 = require('re2');  // npm install re2

// Substitui o regex engine padrão do V8 por RE2 (Google)
const regex = new RE2('([a-zA-Z]+)*');  // padrão "perigoso" mas safe com RE2
console.log(regex.test('aaaaaaaaa!'));  // resposta imediata, sem travar
```

### 4. Timeout por Requisição

```javascript
//  Proteção preventiva  timeout em cada request
const timeout = require('express-timeout-handler');

app.use(timeout.handler({ timeout: 5000 }));  // 5 segundos máximo
```

---

## 🔗 Chain Exploits

```
ReDoS em validação de email no login  DoS do servidor durante pico de tráfego
ReDoS em API pública + Node.js single-thread  1 request = servidor inteiro travado
ReDoS em validação de input de formulário  DoS seletivo (enviar muitas requisições)
ReDoS em middleware de auth  bypass de autenticação por timeout
```

---

## 📌 Referências
- [[business-logic-flaws]]
- [[http-security-headers]]
- [ReDoS Checker Online](https://devina.io/redos-checker)
- [Vuln-Regex-Detector](https://github.com/nicowillis/vuln-regex-detector)
- [OWASP ReDoS](https://owasp.org/www-community/attacks/ReDoS)
