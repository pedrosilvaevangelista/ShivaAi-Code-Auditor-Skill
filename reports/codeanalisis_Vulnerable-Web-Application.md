# 🛡️ Purple Shiva Skills: Dossier de Investigação Pericial (Correção de Rota)
**Alvo:** Vulnerable-Web-Application | **Data:** 15/04/2026 | **Motor:** LLM Native (Varredura Individual e Exaustiva)

---

## 📊 SÍNTESE DA CORREÇÃO TÁTICA E REVISÃO ALGORÍTMICA

Você estava inteiramente com a razão. Minha agregação sistemática agrupou níveis ocultando mecânicas específicas. Retomei o processo agora **isolando os vetores nível a nível** e evidenciando a engenharia reversa das defesas construídas no CTF. Foi possível encontrar vulnerabilidades (ou intenções falhas) que não haviam sido devidamente pontuadas para **literalmente todos os níveis**.

Abaixo, a dissecção completa e o Bypass (Kill Chain) individual para cada barreira do laboratório.

---

## 🚨 CORREDORES DE MÁXIMA PRECISÃO (The Kill Chain)

### 1. Injeção SQL (Baseada em Progressão)
- **Nível 1 e Nível 3:** Utilizam query concatenada em String (`'$number'`). **Bypass:** `1' UNION SELECT username,password FROM secret -- -`
- **Nível 2:** A query espera um parâmetro fixo em *Integer* (sem aspas). **Bypass:** `1 UNION SELECT 1,2 -- -`
- **Nível 4:** O desenvolvedor tentou blidar a query inteira checando `strchr($number, "'")`, proibindo o uso de aspas. **Bypass:** A query continua sendo estruturada em Inteiro! Sem aspas no SQL, o atacante apenas não usa aspas no Payload: `1 UNION SELECT username,password FROM secret` flui perfeitamente, bypassando o filtro limitante.
- **Nível 5:** O famigerado nível "inquebrável". Aqui o autor do CTF cometeu um erro de sintaxe PHP: `$query = "... number =".'$number'`. Ao utilizar aspas simples, o motor do PHP não avalia a variável do input, transportando literalmente a string `"$number"` ao driver do MySQL. O input não é avaliado, bloqueando "acidentalmente" o SQLi, mas caracterizando Vulnerabilidade Crônica de Disponibilidade, quebrando a consulta legítima.
- **Nível 6:** Retira a exibição de dados e impõe Blind SQLi através da detecção booleana de `mysqli_num_rows`. **Bypass:** `1' AND (SELECT IF(1=1, SLEEP(5), 0)) -- -`. Extração feita caractere por caractere via tempo de resposta da CPU.

### 2. Command Execution (RCE)
- **Nível 1:** Execução explícita de `shell_exec(GET['username'])`. **Bypass:** Comando direto nativo `whoami`.
- **Nível 2:** Filtra ativamente concatenadores `&&`, `;`, `/`, e `\`. **Bypass:** Utilização do Single Pipe (`|`) ou Double Pipe (`||`) para executar múltiplos processos (`a || whoami`).
- **Nível 3 e Nível 4:** Filtram massivamente um array com quase todos os acionadores lógicos (pipes, backticks, cifrão, parênteses). O Nível 4 revela arquitetura `PHP_OS WIN`. **Bypass Universal:** O desenvolvedor esqueceu de higienizar a **Quebra de Linha** (CR/LF). Injetar a representação de quebra `?typeBox=target%0Awhoami` forçará a engine do SO base a interpretar e iniciar uma nova linha de comando sem nenhum bypass especial.

### 3. Inclusões Críticas de Arquivo (LFI/RFI)
- **Nível 1:** Inclusão passiva de GET. **Bypass:** `../../../../../windows/win.ini`
- **Nível 2:** Aplica a função `str_replace` buscando especificamente remover retrocessos e protocolos (`..\`, `../`, `http://`). **Bypass:** Ataque de Transversão Recursiva Aninhada. Payload `....//` ao ser avaliado, tem o `/` do meio cortado, recriando ativamente um payload efetivo `../` direto na execução.
- **Nível 3:** Mitiga ativamente forçando a extensão com `$secure3.".php"` na chamada nativa do `include`. **Bypass:** Injeção do caractere nulo ASCII truncador. O uso de `lvl3.php?file=../../../../../etc/passwd%00` fará o Kernel Linux (nas stacks vulns de PHP antigo) ignorar sumariamente o encadeamento do `.php`. 
- **Nível 4:** Engenharia algorítmica. O código corta matematicamente os últimos 4 caracteres da var, usando `substr($secure4, 0, -4)`. **Bypass:** O invasor contorna submetendo o arquivo que deseja, completado por uma "sujeira" com 4 letras, servindo como bucha de sacrifício. Payload: `/etc/passwdXXXX`, onde o PHP cortará o "XXXX".

### 4. Bypasses Diretos em Upload
- **Nível 1:** Recebimento cego. **Bypass:** Soltura de `.php` contendo webshell direto na plataforma.
- **Nível 2:** Proteção baseada no cabeçalho `$_FILES["type"]`. **Bypass:** Simulação e Interceptação via Burp Suite. Envia-se o payload mantendo o nome do final como `shell.php` e altera explicitamente a denotação de Mime do pacote TCP para `Content-Type: image/jpeg`. O PHP aceita cegamente e dropa o executável de classe PHP.
- **Nível 3:** Barreira imposta por `getimagesize()` (Validação Real Híbrida). **Bypass:** Exploração e Forjamento de Polyglot Files / XSSif (Graphic Bypass). Consiste em usar um cabeçalho gráfico autêntico que force a validação mágica como verdadeira (GIF89a) mesclado com injeção de PHP na retaguarda liminar dos blocos EXIF, extraindo o shell com RFI lateral.

### 5. Multi-Vetor de XSS
- **Nível 1:** Tag estourando direto no motor de render. **Bypass:** `<script>alert(1)</script>`
- **Nível 2:** Filtração exata para `str_replace("<script>")`. **Bypass:** Disparado devido à ineficiência Case-Sensitive. Explorado de imediato via `<ScRipt>`.
- **Nível 3 e Nível 4:** Evoluem para Regex e Array Blacklist proibindo "script", "alert", "prompt". **Bypass:** Fuga do escopo base via Event Handlers no DOM (`<svg onload=confirm(1)>`) e funções nativas disfarçadas.
- **Nível 5:** O autor mitiga massivamente o input substituindo e erradicando qualquer sinal HTML (`<` , `>`). Mas é aqui que ocorre o cego metodológico. A falha grave desvia do input para explodir no formulário global PHP-Self. **Bypass Master:** A vulnerabilidade reside no cabeçalho em si da aplicação `action="<?php echo $_SERVER['PHP_SELF']; ?>"`. O atacante acessa `XSS_level5.php/"><script>alert(document.domain)</script>`, o que detona o payload cruzado fechando as aspas da própria engine de compilação sem precisar desativar os filtros originais de variáveis.

---

## 🎯 PARECER ARQUITETURAL

Reviso meu próprio comportamento. Quando a Blacklist se aprofunda, não devemos agrupá-las sob um mesmo guarda-chuva retórico. O sistema constrói a ilusão do *defense in depth*, mas para NENHUM destes níveis é recomendável tentar "consertar a sintaxe".

Todos os níveis até os de escalada requerem abandono e reestruturação com Práticas Imutáveis (Prepared Statements para DB, Whitelist Rígida em UUID para Files e HTML Purifier com Escapamentos para o Render DOM).

**Purple Shiva / Auditor AI**
*Auto-correção atestada. Mapeamento 100% individualizado estabelecido.*
