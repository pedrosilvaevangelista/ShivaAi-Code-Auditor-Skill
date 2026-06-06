# Mishandling of Exceptional Conditions (Failing Open)

**Tags:** #medium #high #error-handling #fail-open #dos #state-corruption
**OWASP:** A10:2025 Mishandling of Exceptional Conditions
**CVSS Base:** 5.3 (Medium → Information Leak) — 7.5 (High → DoS or State Corruption)

---

## 📖 What is it

A completely new category in OWASP 2025. This flaw occurs when applications do not anticipate, catch, and safely recover from unexpected errors (exceptions). 

Instead of **"Failing Securely" (Fail Closed)**, the application may:
1. Crash and leak sensitive internal state (stack traces).
2. Leave database transactions half-completed, corrupting business state.
3. Fail to release memory/locks, leading to Resource Exhaustion (DoS).
4. Bypass security checks because an exception interrupted the validation logic (**Failing Open**).

---

## 🔍 `grep_search` Tactics

```
# Look for empty catch blocks (swallowed exceptions)
catch (Exception e) {}
catch(e) { console.log(e); }
except Exception pass

# Look for generic catches without specific handling
catch (Exception
except Exception as e:

# Look for missing finally blocks (Resource leaks)
.lock(
.acquire(
fopen(
db.beginTransaction(

# Look for debug mode or stack trace exposure
stackTrace
print_exc
res.send(err.stack)
APP_DEBUG=true
```

---

## 💣 Vulnerability Patterns & Scenarios

### 1. Failing Open (CWE-636)
Security controls must always default to denying access. If an error occurs during the authorization check, the user should be blocked, not permitted.

```javascript
//  VULNERABLE — Failing Open
async function isUserAdmin(userId) {
    try {
        const result = await db.query('SELECT role FROM users WHERE id = ?', [userId]);
        return result.role === 'admin';
    } catch (err) {
        // Database timeout or error? The dev assumed "true" to avoid breaking the app.
        // Attacker forces a DB error (e.g. sending a malformed UUID) and becomes Admin.
        return true; 
    }
}
```

```javascript
//  CORRECT — Failing Closed (Secure)
async function isUserAdmin(userId) {
    try {
        const result = await db.query('SELECT role FROM users WHERE id = ?', [userId]);
        return result.role === 'admin';
    } catch (err) {
        // Log the error securely and DENY access
        logger.error(`Admin check failed for ${userId}`);
        return false; 
    }
}
```

### 2. Transaction State Corruption (OWASP Scenario #3)
Financial or critical multi-step operations must be atomic. If an error occurs midway, everything must be rolled back.

```java
//  VULNERABLE — No rollback on exception
public void transferMoney(Account from, Account to, double amount) {
    db.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", amount, from.id);
    
    // What if the network fails here? Or the database crashes?
    // The money is deducted from the sender, but never reaches the receiver!
    
    db.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", amount, to.id);
}
```

```java
//  CORRECT — Transactional Rollback
public void transferMoney(Account from, Account to, double amount) {
    try {
        db.beginTransaction();
        db.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", amount, from.id);
        db.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", amount, to.id);
        db.commit();
    } catch (Exception e) {
        db.rollback(); // Undo the deduction! Fail closed.
        throw new TransactionException("Transfer failed", e);
    }
}
```

### 3. Resource Exhaustion / Denial of Service (OWASP Scenario #1)
If exceptions bypass the code that releases resources (memory, file handles, DB connections), an attacker can intentionally trigger exceptions to exhaust server resources.

```python
#  VULNERABLE — Lock is never released if do_work() throws an exception
lock.acquire()
do_work()  # Attacker causes this to throw ValueError
lock.release() # This line is never reached. Deadlock!
```

```python
#  CORRECT — Using finally or context managers
try:
    lock.acquire()
    do_work()
finally:
    lock.release() # Always executes, even on exception

# Better in Python:
with lock:
    do_work()
```

### 4. Stack Trace Exposure (OWASP Scenario #2)
Revealing internal code structure or database queries provides a roadmap for attackers to craft precise SQL Injection or Deserialization payloads.

```javascript
//  VULNERABLE — Sending stack to client
app.use((err, req, res, next) => {
    res.status(500).json({ error: err.message, stack: err.stack });
});
```

```javascript
//  CORRECT — Generic client message, detailed server log
app.use((err, req, res, next) => {
    logger.error("System Error", { stack: err.stack });
    res.status(500).json({ error: "An unexpected error occurred." });
});
```

---

## 🛡️ Auditor's Playbook

When auditing error handling, follow these rules:
1. **Never swallow exceptions:** Empty `catch` blocks are a red flag. The system is entering an unknown state silently.
2. **Global Exception Handler:** Verify the framework has a global safety net that catches unhandled exceptions and returns a generic 500 error without leaking the stack.
3. **Transaction Boundaries:** Check financial logic for explicit `rollback()` calls in `catch` blocks.
4. **Rate Limit Exceptions:** An attacker brute-forcing errors shouldn't be able to fill up the disk with logs. (See [[log-injection-tampering]]).

---

## 🔗 Chain Exploits

```
Verbose Error (Stack Trace) → Exposes DB structure → Blind SQLi becomes Trivial SQLi
Unhandled Exception in Auth Middleware → Execution continues without auth → RCE
Resource Exhaustion via upload exception → Server Crash → Availability Loss
Half-completed transaction → Salami Slicing attack → Infinite money generation
```

---

## 📌 References
- [[business-logic-flaws]]
- [[security-misconfiguration-default-debug]]
- [[log-injection-tampering]]
