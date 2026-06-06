# Application Resilience & DoS (Denial of Service)

**Tags:** #high #dos #availability #resilience #resource-exhaustion
**OWASP:** X01:2025 Lack of Application Resilience
**CVSS Base:** 7.5 (High → Availability impact)

---

## 📖 What is it

A systemic weakness in how applications respond to stress, failures, and edge cases. When an application does not gracefully handle resource constraints, it results in Denial of Service (DoS) or cascading failures.

This replaces the older "Denial of Service" classification by focusing on the *root cause* (lack of resilience) rather than the symptom.

---

## 🔍 `grep_search` Tactics

```
# Look for unbounded loops and recursion
while (true)
while (1)
recursive_function(
find_all(

# Look for massive data loading without pagination
.findAll()
SELECT * FROM
ReadAllBytes

# Look for missing timeouts
timeout=None
timeout: 0
no_timeout

# Look for uncompressed data limits
zlib.decompress
gzip.unzip
```

---

## 💣 Vulnerability Patterns & CWEs

### 1. Uncontrolled Resource Consumption (CWE-400)
**Scenario:** An endpoint performs a heavy CPU or database operation but has no rate limits, pagination, or queueing.
```javascript
//  VULNERABLE — Synchronous blocking operation on the main thread
app.get('/api/export', (req, res) => {
    // Blocks Node.js event loop for all other users!
    const data = crypto.pbkdf2Sync('password', 'salt', 10000000, 64, 'sha512');
    res.send(data);
});
```
**Fix:** Offload heavy operations to worker threads (RabbitMQ, Celery) or use asynchronous non-blocking calls.

### 2. Data Amplification / Zip Bomb (CWE-409)
**Scenario:** The application accepts compressed files (ZIP, GZIP) and decompresses them entirely in memory without checking the expansion ratio.
```python
#  VULNERABLE — Reading a zip bomb into memory
import zipfile
with zipfile.ZipFile('user_upload.zip', 'r') as z:
    for filename in z.namelist():
        data = z.read(filename) # 1MB zip expands to 40GB in RAM -> OOM Crash
```
**Fix:** Validate compression ratios. Refuse to decompress files that expand beyond a predefined safe threshold (e.g., 50MB).

### 3. Uncontrolled Recursion / Infinite Loops (CWE-674, CWE-835)
**Scenario:** A parser or recursive function handles user input but lacks a depth limit.
```java
//  VULNERABLE — GraphQL Deep Nesting
// query { author { posts { author { posts { ... } } } } }
public Author getAuthor() {
    return this.posts.stream().map(Post::getAuthor)...
}
```
**Fix:** Implement depth limits for JSON/XML parsing, GraphQL query depth limits, and timeout circuit breakers.

---

## 🛡️ Resilience Architecture (Fixes)

1. **Circuit Breakers:** If an external API fails 5 times, open the circuit and stop trying for 30 seconds to prevent cascading failures.
2. **Bulkheads:** Isolate resource pools. E.g., The video processing queue should not share CPU cores with the authentication service.
3. **Graceful Degradation:** If the recommendation engine fails, don't crash the homepage. Show default items instead.
4. **Timeouts:** *Every* network request and database query must have a strict timeout.
5. **Pagination:** Never return `SELECT *`. Always enforce `LIMIT 100`.

---

## 📌 References
- [[mishandling-exceptional-conditions]]
- [[anti-automation-bot-protection]]
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
