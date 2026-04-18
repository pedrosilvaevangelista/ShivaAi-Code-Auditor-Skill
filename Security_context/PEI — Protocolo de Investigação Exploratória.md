# PEI — Protocolo de Investigação Exploratória

**Tags:** #metodologia #protocolo #auditoria #sast #dast
**Tipo:** Referência de processo — não é uma vulnerabilidade

---

## 📖 O que é

O PEI é a metodologia de auditoria estruturada do motor Purple Shiva. Define a ordem e a profundidade das fases de análise para maximizar a cobertura enquanto respeita a janela de contexto finita.

---

## 🔄 Fases da Auditoria

### Fase 0 — Avaliação de Stack e Heurística Probabilística

1. Identificar: linguagem, framework, bibliotecas de dependência
   - Ler: `composer.json`, `package.json`, `requirements.txt`, `pom.xml`, `web.config`, `Gemfile`
2. **Se existirem arquivos IaC** (`.tf`, `docker-compose.yml`, `.github/workflows/*.yml`, `k8s/`):
   - Priorizar [[IaC Security — Docker Kubernetes Terraform]] e [[CI-CD Pipeline Attack Surface]] **antes** do código da aplicação
3. Construir o **Mapa de Probabilidades**:
   - Listar as 3 classes de vulnerabilidade mais prováveis dado o stack
   - Ordenar por prioridade de busca

```
Stack → Vulnerabilidades mais prováveis
─────────────────────────────────────────────────────
PHP legado + mysql_query   → SQLi por concatenação
Node.js + child_process    → RCE / Prototype Pollution
.NET + BinaryFormatter     → Deserialização Insegura
Java + ObjectInputStream   → Java Deserialization
Python + pickle/yaml.load  → Deserialization RCE
Qualquer + JWT alg:none    → Algorithm Confusion
App com upload             → Unrestricted File Upload
App com template engine    → SSTI
App com GraphQL            → Introspection + Batch Attack
App com MongoDB/Firebase   → NoSQL Injection
App com LDAP/AD            → LDAP Injection
App com OAuth/SAML         → Protocol Attacks
App com WebSocket          → CSWSH
```

---

### Fase 0.5 — Análise de Dependências por CVE

> **Executar antes de qualquer leitura de código.** Uma dependência vulnerável já justifica finding Crítico independente da qualidade do código.

Ler os manifestos e cruzar com CVEs conhecidos: → [[Análise de Dependências por CVE]]

---

### Fase 1 — Infiltração Total e Mapeamento de Superfície

- `list_dir` recursivo — explorar **todos** os diretórios
- Mapear:
  - **Pontos de entrada:** forms, APIs REST/GraphQL, parâmetros GET/POST, WebSockets
  - **Camada de banco:** queries SQL brutas, ORMs com `.raw()`, NoSQL
  - **Autenticação/autorização:** middleware, decorators, guards
  - **Uploads:** destinos, validações, nomes de arquivo
  - **Inclusões de arquivo:** `include()`, `require()`, `import file`
  - **Integrações externas:** HTTP clients, webhooks, parsers XML/JSON

---

### Fase 2 — Identificação de Critical Sinks e Source-to-Sink Tracing

**`grep_search` sequencial** nos sinks mais perigosos (um por vez):

#### Execução / Injeção
```
exec(          → Command Injection
eval(          → JS/Python eval RCE
system(        → Shell RCE
shell_exec(    → PHP RCE
include(       → LFI/RFI
query(         → SQLi
find({         → NoSQL Injection
$where(        → MongoDB JS Injection
ldap_search(   → LDAP Injection
ldap_bind(     → LDAP Auth Bypass
unserialize(   → PHP Deserialization
ObjectInputStream  → Java Deserialization
pickle.loads(  → Python Deserialization
BinaryFormatter    → .NET Deserialization
```

#### Frontend / Client-Side
```
innerHTML      → XSS Stored/Reflected
dangerouslySetInnerHTML  → XSS React
document.write(          → XSS DOM
eval(                    → XSS DOM
location.hash            → DOM XSS Source
addEventListener('message'  → postMessage sem Origin
```

#### Infraestrutura / Protocolo
```
fetch(url         → SSRF candidato
axios.get(url     → SSRF candidato
curl_exec(        → SSRF
file_get_contents($url  → SSRF
redirect(req      → Open Redirect
header("Location: → CRLF Injection
Set-Cookie        → Cookie sem flags
github.event.pull_request.title  → CI/CD Script Injection
privileged: true  → Docker privilege escalation
```

#### Criptografia
```
md5(           → Hash inseguro de senha
sha1(          → Hash inseguro de senha
Math.random()  → Aleatoriedade insegura (tokens)
SECRET_KEY =   → Segredo hardcoded
verify=False   → TLS desabilitado
AES/ECB        → Modo de cifra fraco
```

---

### Fase 3 — Análise de Lógica de Negócio e Fronteiras de Confiança

- Mapear o fluxo **intencional** da aplicação
- Tentar subvertê-lo logicamente: → [[Business Logic Flaws]]
- Identificar trust boundaries violadas:
  - Cookies não assinados usados para autorização
  - Headers `X-Forwarded-For` confiados sem verificação
  - Dados de banco re-utilizados como comandos internos

---

### Fase 4 — Validação Ad-Hoc (Prova de Conceito)

Para vulnerabilidades que exigem confirmação contextual:
1. Criar script Python efêmero em `.tmp/`
2. Executar via terminal
3. Coletar evidência (output, status code, timing)
4. Descartar o script

---

### Fase 4.5 — Limpeza Pós-Scan (OBRIGATÓRIA)

```powershell
# Windows
Remove-Item -Path ".tmp/*" -Recurse -Force -ErrorAction SilentlyContinue

# Linux
rm -rf .tmp/*
```

**Justificativa:** Scripts DAST podem conter payloads, URLs de alvos e credenciais extraídas. OpSec crítico.

---

### Fase 5 — Síntese do Dossiê de Elite

Gerar: `reports/codeanalisis_[projeto].md`

Estrutura de cada finding: → [[Template de Finding]]

---

## 🧠 Regras Anti-Alucinação

1. **Regra do DNA:** Toda afirmação de vulnerabilidade DEVE ter âncora em arquivo + linha exata
2. **Nunca especule** sobre comportamento de função sem ter lido o arquivo que a define
3. `grep_search` primeiro → leia apenas os arquivos retornados
4. Ao sentir incerteza, leia o arquivo antes de prosseguir

---

## 📌 Referências
- [[Template de Finding]]
- [[Matriz de Severidade]]
- [[Chain Exploit — Efeito Borboleta]]
- [[Taint Analysis Cognitivo]]
