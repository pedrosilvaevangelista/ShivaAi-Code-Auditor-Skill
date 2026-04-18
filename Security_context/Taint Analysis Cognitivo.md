# Taint Analysis Cognitivo

**Tags:** #metodologia #taint-analysis #source-to-sink #fluxo-de-dados
**Tipo:** Técnica de análise mental — não é uma vulnerabilidade

---

## 📖 O que é

Taint Analysis cognitivo é a técnica de **rastrear mentalmente o fluxo de um dado do ponto de entrada (Source) até o ponto de execução perigosa (Sink)**, identificando onde a "cadeia de custódia" do dado é rompida.

> *"Um dado não sanitizado que viaja do input do usuário até uma query SQL é uma vulnerabilidade. Mas é necessário provar o caminho completo."*

---

## 🗺️ Modelo Source → Transform → Sink

```
SOURCE                    TRANSFORM                     SINK
─────────────────────────────────────────────────────────────
Input do usuário    →    Middlewares / Filtros    →    Execução
(Dado contaminado)       (Pode sanitizar ou não)       (Perigo)
```

---

## 🎯 Sources — Onde o Dado Entra

### HTTP / Web
```
req.body.*           → POST JSON/form body
req.query.*          → Query string (?param=value)
req.params.*         → URL parameters (/users/:id)
req.headers.*        → HTTP headers
req.cookies.*        → Cookies
$_GET, $_POST        → PHP superglobals
$_COOKIE, $_SERVER   → PHP
request.GET, POST    → Django/Flask
request.args         → Flask
params[:name]        → Rails
```

### Banco de Dados (Second-Order Sources)
```
User.find().name     → dado salvo anteriormente pode ser tainted
db.query("SELECT")   → resultado de query pode ser reutilizado como input
redis.get(key)       → cache infectado
memcache.get(key)    → cache infectado
```

### Arquivos / Environment
```
os.environ['X']      → variáveis de ambiente
open(filename).read()→ conteúdo de arquivo
yaml.load(file)      → arquivo de config YAML
JSON.parse(config)   → arquivo de config JSON
```

---

## ⚙️ Transforms — O que Acontece no Meio

### Sanitizações que funcionam (geralmente)
```python
html.escape(data)          → XSS mitigation
bleach.clean(data)         → XSS mitigation
parameterized query        → SQLi mitigation
shlex.quote(data)          → Command injection mitigation
json.dumps(data)           → não resolve SQLi, mas escapa JSON
urllib.parse.quote(data)   → URL encoding (parcial para SQLi)
```

### Sanitizações que falham (falsas proteções)
```python
data.replace("'", "''")    → bypassed com encoding
data.replace(";", "")      → bypassed com alternativas
data.lower()               → não sanitiza injeção
data.strip()               → não sanitiza injeção
blacklist de palavras       → bypassed com variantes
regex simples              → bypassed com encoding
```

### Transforms que passam o taint adiante
```python
f"SELECT * FROM users WHERE id = {data}"  # string formatting → sink mantém taint
"query" + data                             # concatenação → taint permanece
data.encode('utf-8')                       # encoding → taint permanece
base64.b64decode(data)                     # decode → taint permanece
json.loads(data)                           # parsing → taint permanece
```

---

## 🎯 Sinks — Onde o Perigo Mora

### SQL (SQLi)
```
db.execute(query)
cursor.execute(query)
conn.query(query)
Model.raw(query)
db.query(raw_sql)
```

### Sistema (Command Injection)
```
os.system(cmd)
subprocess.run(cmd, shell=True)
exec(code)
eval(code)
shell_exec(cmd)
Runtime.getRuntime().exec(cmd)
```

### Arquivo (Path Traversal / LFI)
```
open(path)
os.path.join(base, user_input) → open()
include(user_input)
require(user_input)
fs.readFile(path)
```

### HTML (XSS)
```
element.innerHTML = data
document.write(data)
dangerouslySetInnerHTML={{ __html: data }}
render_template_string(f"...{data}...")
```

### Rede (SSRF)
```
requests.get(url)
fetch(url)
axios.get(url)
curl_exec(url)
HttpClient.get(url)
```

---

## 🔄 Protocolo de Análise

```
Para cada Sink identificado via grep_search:

1. IDENTIFICAR: o que alimenta este sink?
   → Rastrear para cima: de onde vem a variável passada para o sink?

2. RASTREAR: percorrer o caminho de volta até o Source
   → Cada função intermediária: lê — a variável vem de onde?
   → Mapeie: req.body.X → sanitizeInput(X) → buildQuery(X) → exec(query)

3. AVALIAR: há sanitização real no caminho?
   → Whitelist explícita? (confiável)
   → Blacklist? (não confiável — provavelmente bypassável)
   → Parametrização? (confiável para SQLi)
   → Encoding? (pode não ser suficiente)

4. CONFIRMAR: a sanitização ocorre no contexto correto?
   → Sanitização para XSS não protege de SQLi
   → escapeshellarg() não protege de SQLi
   → htmlspecialchars() não protege de shell

5. ANCORAR: documentar arquivo + linha exata de cada ponto da chain
```

---

## 🧠 Micro-Grafo de Fluxo de Dados

Ao analisar cada arquivo, registrar mentalmente:

```
Arquivo: routes/user.js
─────────────────────────────────
ENTRADA:  req.body.username  → route POST /login
PASSA:    → controllers/auth.js → authenticateUser(username, password)
CHEGA:    → models/User.js → db.query(`SELECT * WHERE name='${username}'`)
SINK:     db.query() com concatenação direta → SQLi CONFIRMADO
─────────────────────────────────
EVIDÊNCIA: routes/user.js:42 → controllers/auth.js:78 → models/User.js:23
```

---

## 💡 Cross-File Correlation

Para projetos grandes, usar `grep_search` **por variável específica** para rastrear o taint cross-file:

```bash
# Rastrear onde 'username' é usado após entrada
# Grep por todos os usos da variável em todo o projeto
grep -r "username" --include="*.py"

# Rastrear a função que processa o dado
# Depois grep pela função específica para ver onde ela é chamada
grep -r "authenticateUser" --include="*.js"
```

---

## 📌 Referências
- [[PEI — Protocolo de Investigação Exploratória]]
- [[Second-Order Injection]]
- [[SQL Injection (SQLi)]]
- [[Command Injection & RCE]]
