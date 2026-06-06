# Security Misconfiguration & Default Settings

**Tags:** #high #misconfiguration #debug #cloud #infrastructure
**OWASP:** A02:2025 Security Misconfiguration
**CVSS Base:** 5.0 - 9.8 (Varies heavily depending on what is exposed)

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

### 1. Spring Boot Actuator Exploitation
If `/actuator/env` or `/actuator/heapdump` is exposed:
```bash
curl -s http://target.com/actuator/env | jq
# Attacker dumps the environment variables, looking for AWS_SECRET_ACCESS_KEY or DB passwords.
```

### 2. Google Dorking for Directory Listings
```
intitle:"index of" "database.yml"
intitle:"index of" inurl:backup
```

### 3. S3 Bucket Enumeration
```bash
aws s3 ls s3://company-production-assets --no-sign-request
# If successful, the bucket is public.
```

---

## 📌 References
- [OWASP A02:2025 Security Misconfiguration](https://owasp.org/Top10/)
- [[iac-security-docker-kubernetes-terraform]]
- [[http-security-headers]]
- [[cors-misconfiguration]]
- [[xml-external-entity-xxe]]
