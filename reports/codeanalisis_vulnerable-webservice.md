# 🛡️ Purple Shiva Skills: Dossier de Investigação Nativa
**Alvo:** vulnerable-webservice | **Data:** 15/04/2026 | **Motor:** LLM Native (The No Script Paradigm)

---

## 📊 SÍNTESE DA INVESTIGAÇÃO

Auditoria concluída com sucesso no projeto `vulnerable-webservice` ("Seguros Confiáveis"). Diferente de um varredor estático genérico, a investigação exploratória nativa conseguiu entender a arquitetura do projeto e correlacionar vulnerabilidades lógicas e de infraestrutura, identificando um total de **6 caminhos críticos** para o comprometimento total (Remote Code Execution e Database Takeover).

---

## 🚨 CORREDORES DE COMPROMETIMENTO (The Kill Chain)

### 1. Injeção SQL Base (Authentication Bypass)
- **Local:** `index.php` (Linha 16)
- **Análise:** O sistema aceita os parâmetros `username` e `password` via `$_POST` e os concatena diretamente numa Query `SELECT`. Sem sanitização, qualquer aspas simples (`'`) quebra o statement original.
- **Prova de Conceito Teórica:** Inserir `' OR 1=1 -- -` no campo de usuário loga o invasor como o primeiro usuário do banco (provavelmente o Administrador).

### 2. Arbitrary File Inclusion (LFI / RFI)
- **Local:** `pages/logs.php` (Linha 28)
- **Análise:** A rota `logs.php?page=...` pega o input do usuário e o injeta diretamente na diretiva `include($page)`. Isso permite a um invasor contornar o diretório de logs e ler qualquer arquivo do sistema operacional, ou mesmo incluir shells em PHP via *wrapper* ou chamadas remotas (RFI) se a configuração do PHP não barrar.
- **Prova de Conceito Teórica:** Acesso via navegador a `http://alvo/pages/logs.php?page=/etc/passwd` despejará os hashes do sistema operacional.

### 3. Upload Inseguro Levando a RCE (Remote Code Execution)
- **Local:** `pages/customers.php` (Linha 22)
- **Análise:** O formulário de "Novo Segurado" recebe um dado via `$_FILES['foto']` e utiliza a função nativa `move_uploaded_file()` salvando no diretório `../storage/uploads/`. Não há lista branca (whitelist) de extensões `.png/.jpeg` nem verificação de *MIME Type*. 
- **Exploitation:** Um atacante autenticado pode enviar um webshell `shell.php` e subsequentemente acessá-lo via `/storage/uploads/shell.php?cmd=whoami`.
- **Agravante:** Como o `docker-compose.yml` especifica `user: root`, o PHP executará o webshell com privilégios máximos de ROOT no container.

### 4. Cross-Site Scripting Refletido (XSS)
- **Local:** `pages/policies.php` (Linha 27)
- **Análise:** A tela de apólices recupera o termo da busca na variável `$search` (provinda de `$_GET['q']`) e faz a impressão direta no HTML (`<?= $search ?>`). Como não utiliza o `htmlspecialchars()`, as tags HTML fluem integralmente para o browser.
- **Prova de Conceito Teórica:** `http://alvo/pages/policies.php?q=<script>alert("XSS")</script>`

### 5. Injeção SQL Pós-Auth (Union-Based)
- **Local:** `pages/policies.php` (Linha 12)
- **Análise:** A mesma vulnerabilidade de XSS carrega consigo uma injeção SQL, pois o parâmetro `status` e a string de busca `q` são acoplados semanticamente à query principal do painel de controle com `LIKE '%$search%'`.

### 6. Fragilidade de Infraestrutura e Hardcoding
- **Local:** `docker-compose.yml`
- **Análise:** 
  1. O container web é forçado a executar como `user: root`. Qualquer RCE na aplicação (como a da etapa 3) vira um *Root Shell* instantâneo dentro da infra.
  2. Uso do `volumes: .:/var/www/html` espelha os arquivos do host hostil.
  3. Senha primária exposta: `MYSQL_ROOT_PASSWORD: root`.

---

## 🎯 PROTOCOLO DE REMEDIAÇÃO E RECOMENDAÇÕES

A aplicação foi montada com vulnerabilidades deliberadas gravíssimas pelo design (Web Lab). Para torná-la segura de fato:
1. Submeter **todos** os canais do `mysqli` para usar **Prepared Statements** (parâmetros tipados com `bind_param`), matando a via de SQLi.
2. Na aba de uploads, trocar o nome do arquivo para um `md5` ou `uuid` aleatório sem uso da extensão da requisição, embutindo a checagem com `getimagesize()` ou bibliotecas como GD.
3. Jamais utilizar a função `include()` ou `require()` recebendo dados baseados na `query string`. Substituir por leitura de buffer purificado (`file_get_contents` se for só texto logado).
4. Evite usar `user: root` no Dockerfile. O Apache deve circular na roda do usuário `www-data` no namespace do kernel.

**Engenheiro Auditor AI**
*Sistema de Investigação Autônomo concluído com sucesso.*
