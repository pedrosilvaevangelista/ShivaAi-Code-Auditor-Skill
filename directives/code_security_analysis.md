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

---

## Protocolo de Investigação Exploratória (PEI)

### Fase 0 — Avaliação de Stack e Heurística Probabilística
- Identificar: linguagem, framework, bibliotecas (`composer.json`, `package.json`, `requirements.txt`, `pom.xml`, `web.config`).
- Construir mentalmente o **Mapa de Probabilidades**: listar as 3 classes de vulnerabilidade mais prováveis dado o stack, na ordem de ataque.

### Fase 1 — Infiltração Total e Mapeamento de Superfície
- Explorar recursivamente *todos* os diretórios e arquivos, sem exceção.
- Mapear: pontos de entrada (forms, APIs, params GET/POST), camada de banco (queries, ORMs), autenticação/autorização, uploads, inclusões de arquivo.

### Fase 2 — Identificação de Critical Sinks e Source-to-Sink Tracing
- `grep_search` focado nos sinks mais perigosos: `exec`, `eval`, `system`, `include`, `query`, `innerHTML`, `dangerouslySetInnerHTML`, `deserialize`, `pickle.loads`, `yaml.load`.
- Para cada sink encontrado, rastrear até a origem do dado. Validar se há sanitização real (*whitelist*) ou apenas filtros ilusórios (*blacklist*).

### Fase 3 — Análise de Lógica de Negócio e Fronteiras de Confiança
- Mapear o fluxo intencional da aplicação e tentar subvertê-lo logicamente.
- Identificar todos os pontos onde o sistema confia implicitamente em dados externos sem assinatura ou verificação.

### Fase 4 — Validação Ad-Hoc (Prova de Conceito)
- Para vulnerabilidades que exigem confirmação contextual (formato de hash, estrutura de JWT, comportamento de regex), criar script Python efêmero em `.tmp/`, rodar, coletar evidência, descartar.

### Fase 5 — Síntese do Dossiê (Relatório)
- Escrever `/reports/codeanalisis_[project_name].md` do zero.
- **Obrigatório em cada finding:** Localização exata (arquivo + linha), fluxo Source→Sink, Prova de Conceito realista, Remediação pela causa-raiz (nunca por filtro adicional).

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
| v1.3 | 15/04/2026 | **Business Logic Flaws, Second-Order Injection, Trust Boundary Violations, Matriz de Severidade com Chain Exploit** |
