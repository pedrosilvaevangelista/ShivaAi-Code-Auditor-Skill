# Unrestricted File Upload — Tactical Pillar

> **Context:** Allowing users to upload files is one of the most dangerous functionalities. If naming, content, and execution are not strictly controlled, it leads to immediate RCE.

---

## 1. Extension Bypass (Evasion)
Filters that only check for `.jpg` or `.png` are often flawed.
- **Blacklist Bypass:** `.php5`, `.phtml`, `.jspx`, `.ashx`, `.cer`, `.config`.
- **Double Extension:** `shell.php.jpg`.
- **Null Byte:** `shell.php%00.jpg` (Legacy PHP).
- **Whitespace/Case:** `shell.phP`, `shell.php. `.

---

## 2. Content-Type & Magic Byte Spoofing
- **Scenario:** Server checks `Content-Type: image/jpeg` header from the request.
- **Tactic:** Attacker sends a PHP script but keeps the `image/jpeg` header (client-controlled).
- **Magic Bytes:** Server checks the first bytes of the file. Attacker injects `GIF89a;` at the start of the PHP webshell.

---

## 3. Path Injection via Filename
- **Scenario:** `SaveAs("uploads/" + file.filename)`.
- **Tactic:** Filename set to `../../shell.php`.
- **`grep_search`:** Check if the application uses the original filename from the request in the filesystem path.

---

## 4. Metadata Exploitation
- **Scenario:** Server processes image metadata (EXIF).
- **Tactic:** Inject PHP/JS/Command code into EXIF tags.
- **Detonation:** If the metadata is later displayed (XSS) or processed by a vulnerable library (ImageMagick - ImageTragick).

---

## 5. Overwriting Critical Files
- **Tactic:** Upload `.htaccess` or `web.config` to change server configuration (e.g., allow execution of `.txt` files as PHP).

---

## Strategic Checklist for Auditor
1. [ ] Locate upload handlers.
2. [ ] Check for extension validation (Whitelist vs Blacklist).
3. [ ] Verify if files are renamed to a UUID/Hash before saving.
4. [ ] Check for `disallow-execution` in the upload directory.
5. [ ] Search for `move_uploaded_file`, `SaveAs`, `MultipartFile`, `upload.single`.

---

*Tags: #file-upload #rce #evasion #webshell #shiva-vault*
