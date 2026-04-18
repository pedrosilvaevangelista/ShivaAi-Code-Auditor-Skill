# EIP — Exploratory Investigation Protocol

**Tags:** #methodology #protocol #audit #sast #dast
**Type:** Process Reference — *not a vulnerability*

---

## 📖 What it is

The EIP is the structured audit methodology for the ShivaAi engine. It defines the order and depth of analysis phases to maximize coverage while respecting the finite context window.

---

## 🔄 Audit Phases

### Phase 0 — Stack Evaluation and Probabilistic Heuristic

1. **Identify:** Language, framework, dependency libraries.
   - Read: `composer.json`, `package.json`, `requirements.txt`, `pom.xml`, `web.config`, `Gemfile`.
2. **If IaC files exist** (`.tf`, `docker-compose.yml`, `.github/workflows/*.yml`, `k8s/`):
   - Prioritize [[iac-security-docker-kubernetes-terraform]] and [[ci-cd-pipeline-attack-surface]] **before** application code.
3. **Build the Probability Map:**
   - List the 3 most likely vulnerability classes given the stack.
   - Order by search priority.

```
Stack — Most Probable Vulnerabilities

Legacy PHP + mysql_query    SQLi via concatenation
Node.js + child_process     RCE / Prototype Pollution
.NET + BinaryFormatter      Insecure Deserialization
Java + ObjectInputStream    Java Deserialization
Python + pickle/yaml.load   Deserialization RCE
Any + JWT alg:none          Algorithm Confusion
App with upload             Unrestricted File Upload
App with template engine    SSTI
App with GraphQL            Introspection + Batch Attack
App with MongoDB/Firebase   NoSQL Injection
App with LDAP/AD            LDAP Injection
App with OAuth/SAML         Protocol Attacks
App with WebSocket          CSWSH
```

---

### Phase 0.5 — Dependency Analysis by CVE

> **Execute before any code reading.** A vulnerable dependency justifies a Critical finding independent of code quality.

Read manifests and cross-reference with known CVEs: [[dependency-analysis-cve]]

---

### Phase 1 — Total Infiltration and Surface Mapping

- Recursive `list_dir` — explore **all** directories.
- Map:
  - **Entry points:** forms, REST/GraphQL APIs, GET/POST parameters, WebSockets.
  - **Database layer:** raw SQL queries, ORMs with `.raw()`, NoSQL.
  - **Authentication/Authorization:** middleware, decorators, guards.
  - **Uploads:** destinations, validations, filenames.
  - **File inclusions:** `include()`, `require()`, `import file`.
  - **External integrations:** HTTP clients, webhooks, XML/JSON parsers.

---

### Phase 2 — Critical Sinks Identification and Source-to-Sink Tracing

**Sequential `grep_search`** on the most dangerous sinks (one at a time):

#### Execution / Injection
```
exec(           Command Injection
eval(           JS/Python eval RCE
system(         Shell RCE
shell_exec(     PHP RCE
include(        LFI/RFI
query(          SQLi
find({          NoSQL Injection
$where(         MongoDB JS Injection
ldap_search(    LDAP Injection
ldap_bind(      LDAP Auth Bypass
unserialize(    PHP Deserialization
ObjectInputStream   Java Deserialization
pickle.loads(   Python Deserialization
BinaryFormatter     .NET Deserialization
```

#### Frontend / Client-Side
```
innerHTML       Stored/Reflected XSS
dangerouslySetInnerHTML   React XSS
document.write(           DOM XSS
eval(                     DOM XSS
location.hash             DOM XSS Source
addEventListener('message'   postMessage without Origin
```

#### Infrastructure / Protocol
```
fetch(url          SSRF candidate
axios.get(url      SSRF candidate
curl_exec(         SSRF
file_get_contents($url   SSRF
redirect(req       Open Redirect
header("Location:  CRLF Injection
Set-Cookie         Cookie without flags
github.event.pull_request.title   CI/CD Script Injection
privileged: true   Docker privilege escalation
```

#### Cryptography
```
md5(            Insecure password hash
sha1(           Insecure password hash
Math.random()   Insecure randomness (tokens)
SECRET_KEY =    Hardcoded secret
verify=False    TLS disabled
AES/ECB         Weak cipher mode
```

---

### Phase 3 — Business Logic and Trust Boundary Analysis

- Map the **intentional** flow of the application.
- Attempt to subvert it logically: [[business-logic-flaws]]
- Identify violated trust boundaries:
  - Unsigned cookies used for authorization.
  - `X-Forwarded-For` headers trusted without verification.
  - Database data re-used as internal commands.

---

### Phase 4 — Ad-Hoc Validation (Proof of Concept)

For vulnerabilities that require contextual confirmation:
1. Create an ephemeral Python script in `.tmp/`.
2. Execute via terminal.
3. Collect evidence (output, status code, timing).
4. Discard the script.

---

### Phase 4.5 — Post-Scan Cleanup (MANDATORY)

```powershell
# Windows
Remove-Item -Path ".tmp/*" -Recurse -Force -ErrorAction SilentlyContinue

# Linux
rm -rf .tmp/*
```

**Justification:** DAST scripts may contain payloads, target URLs, and extracted credentials. Critical OpSec.

---

### Phase 5 — Elite Dossier Synthesis

Generate: `reports/shiva-auditor_[project].md`

Structure for each finding: [[finding-template]]

---

## 🧠 Anti-Hallucination Rules

1. **DNA Rule:** Every vulnerability claim MUST have an anchor in the exact file + line.
2. **Never speculate** about function behavior without having read the file that defines it.
3. `grep_search` first — read only the returned files.
4. When feeling uncertain, read the file before proceeding.

---

## 📌 References
- [[finding-template]]
- [[severity-matrix]]
- [[chain-exploit-butterfly-effect]]
- [[cognitive-taint-analysis]]
