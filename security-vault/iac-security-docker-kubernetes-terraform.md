# IaC Security — Docker, Kubernetes, Terraform

**Tags:** #high #critical #iac #docker #kubernetes #terraform #cloud #infrastructure
**OWASP:** A05:2021 Security Misconfiguration
**CVSS Base:** 8.8 (High) → 10.0 (Critical → privileged container escape)

---

## 📖 What is it

Infrastructure as Code files carry the same weight as application code. A misconfiguration here compromises *everything* running above it. Auditing IaC is **priority 0** when these files are present.

---

## 🔍 `grep_search` Tactics

```
# Docker / Compose
privileged: true
FROM.*latest
ENV.*PASSWORD
ENV.*SECRET
COPY . .
USER root

# Kubernetes
runAsRoot
hostPID: true
hostNetwork: true
allowPrivilegeEscalation: true
securityContext
volumes.*hostPath

# Terraform / AWS
Action.*\*
Resource.*\*
public-read
public-read-write
0.0.0.0/0
acl.*public
sensitive.*false

# CI/CD
github.event.pull_request.title
github.event.issue
head_ref
write-all
echo.*secrets
```

---

## 🐳 Docker — Vulnerabilities

### 1. Container Running as Root

```dockerfile
#  VULNERABLE — root is the default if USER is not defined
FROM ubuntu:latest
COPY . /app
CMD ["python", "app.py"]
# → any RCE in the app = root shell inside the container
```

```dockerfile
#  CORRECT
FROM ubuntu:22.04
RUN groupadd -r appgroup && useradd -r -g appgroup appuser
USER appuser
CMD ["python", "app.py"]
```

### 2. Image Without a Fixed Tag (Supply Chain Risk)

```dockerfile
#  VULNERABLE — latest changes without control
FROM node:latest
FROM python:latest
FROM ubuntu:latest

#  CORRECT — fixed tag and digest
FROM node:20.11.0-alpine3.19@sha256:abc123...
```

### 3. Secret in ENV Layer

```dockerfile
#  VULNERABLE — permanently baked into the image (even in subsequent layers)
ENV DATABASE_PASSWORD=supersecret123
ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE

#  CORRECT — use runtime secrets, never in the image
```

### 4. Missing `.dockerignore` + `COPY . .`

```dockerfile
#  VULNERABLE — without .dockerignore, this copies:
COPY . .
# → .git/, .env, SSH keys, credentials, full source code
```

```
#  Minimal .dockerignore
.git
.env
*.pem
*.key
node_modules
__pycache__
.tmp
```

---

## 🐳 Docker Compose — Vulnerabilities

```yaml
#  CRITICAL — container with full host access (guaranteed escape)
services:
  app:
    privileged: true  

#  CRITICAL — access to host filesystem
    volumes:
      - /:/host

#  HIGH — no network isolation
    network_mode: host
```

**Container escape via `privileged: true`:**
```bash
# From inside the privileged container:
mkdir /mnt/host
mount /dev/sda1 /mnt/host           # mount the host disk
chroot /mnt/host                    # enter the host filesystem
# → full root access to the host
```

---

## ☸️ Kubernetes — Vulnerabilities

### Critical Pod Security Context

```yaml
#  VULNERABLE
spec:
  hostPID: true           # access to host processes
  hostNetwork: true       # no network isolation
  containers:
    - name: app
      securityContext:
        runAsUser: 0      # root
        privileged: true  # full capabilities
        allowPrivilegeEscalation: true
```

```yaml
#  CORRECT
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
    - name: app
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
        readOnlyRootFilesystem: true
```

### Secrets in Environment Variables

```yaml
#  VULNERABLE — hardcoded secret in env
env:
  - name: DB_PASSWORD
    value: "supersecret123"

#  CORRECT — reference to a Kubernetes Secret
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: db-credentials
        key: password
```

---

## 🏗️ Terraform / AWS — Vulnerabilities

### IAM With Wildcard Permissions

```hcl
#  CRITICAL — full permission on the AWS account
resource "aws_iam_policy" "app_policy" {
  policy = jsonencode({
    Statement = [{
      Action   = "*"       # everything
      Resource = "*"       # on everything
      Effect   = "Allow"
    }]
  })
}
```

### Public S3 Bucket

```hcl
#  CRITICAL — publicly readable/writable bucket
resource "aws_s3_bucket" "data" {
  acl = "public-read-write"
}

#  CORRECT
resource "aws_s3_bucket" "data" {
  # no public ACL
}
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### Open Security Group

```hcl
#  CRITICAL — SSH and RDP open to the internet
resource "aws_security_group_rule" "ssh_open" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  # entire internet
}
```

### Sensitive Output Without `sensitive`

```hcl
#  VULNERABLE — exposed in Terraform logs
output "db_password" {
  value = aws_db_instance.main.password
  # sensitive = true  ← missing
}
```

### [NEW] Terraform State Leakage
**How it works:** Even if variables are marked as `sensitive`, they are stored in **plain text** in the `terraform.tfstate` file. If the state file is stored in an insecure S3 bucket or local folder, the secrets are compromised.

### [NEW] Improper K8s Admission Controllers
**How it works:** Admission Controllers (like MutatingAdmissionWebhook) can be used to bypass security policies or inject malicious properties into pods before they are created.

---

## 🔗 Chain Exploits

```
RCE in app + privileged container → Host escape → Total compromise
RCE in app + ENV with AWS keys → Cloud account compromise
Public S3 + .env in bucket → Exposed credentials → Database access
Compromised IAM wildcard → Exfiltration of entire infrastructure
```

---

## 📌 References
- [[ci-cd-pipeline-attack-surface]]
- [[command-injection-rce]]
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NSA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)