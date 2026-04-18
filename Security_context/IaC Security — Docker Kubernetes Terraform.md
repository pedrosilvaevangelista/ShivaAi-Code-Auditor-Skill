# IaC Security — Docker Kubernetes Terraform

**Tags:** #alto #critico #iac #docker #kubernetes #terraform #cloud #infraestrutura
**OWASP:** A05:2021 — Security Misconfiguration
**CVSS Base:** 8.8 (Alto) → 10.0 (Crítico — privileged container escape)

---

## 📖 O que é

Arquivos de Infrastructure as Code têm o mesmo peso que código de aplicação. Uma misconfiguração aqui compromete *tudo* que roda acima dele. Auditar IaC é **prioridade 0** quando os arquivos existem.

---

## 🔍 `grep_search` Táticas

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

## 🐳 Docker — Vulnerabilidades

### 1. Container Rodando como Root

```dockerfile
# ❌ VULNERÁVEL — root é default se USER não for definido
FROM ubuntu:latest
COPY . /app
CMD ["python", "app.py"]
# → qualquer RCE no app = shell de root no container
```

```dockerfile
# ✅ CORRETO
FROM ubuntu:22.04
RUN groupadd -r appgroup && useradd -r -g appgroup appuser
USER appuser
CMD ["python", "app.py"]
```

### 2. Imagem sem Tag Fixa (Supply Chain Risk)

```dockerfile
# ❌ VULNERÁVEL — latest muda sem controle
FROM node:latest
FROM python:latest
FROM ubuntu:latest

# ✅ CORRETO — tag e digest fixos
FROM node:20.11.0-alpine3.19@sha256:abc123...
```

### 3. Segredo em ENV Layer

```dockerfile
# ❌ VULNERÁVEL — fica permanentemente na imagem (mesmo em layers subsequentes)
ENV DATABASE_PASSWORD=supersecreto123
ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE

# ✅ CORRETO — usar secrets em runtime, nunca na imagem
```

### 4. `.dockerignore` Ausente + `COPY . .`

```dockerfile
# ❌ VULNERÁVEL — sem .dockerignore, isso copia:
COPY . .
# → .git/, .env, chaves SSH, credenciais, código-fonte completo
```

```
# ✅ .dockerignore mínimo
.git
.env
*.pem
*.key
node_modules
__pycache__
.tmp
```

---

## 🐳 Docker Compose — Vulnerabilidades

```yaml
# ❌ CRÍTICO — container com acesso total ao host (fuga garantida)
services:
  app:
    privileged: true  

# ❌ CRÍTICO — acesso ao filesystem do host
    volumes:
      - /:/host

# ❌ ALTO — sem isolamento de rede
    network_mode: host
```

**Escape de container via `privileged: true`:**
```bash
# De dentro do container privilegiado:
mkdir /mnt/host
mount /dev/sda1 /mnt/host           # monta o disco do host
chroot /mnt/host                    # entra no filesystem do host
# → acesso root completo ao host
```

---

## ☸️ Kubernetes — Vulnerabilidades

### Pod Security Context Crítico

```yaml
# ❌ VULNERÁVEL
spec:
  hostPID: true           # acesso aos processos do host
  hostNetwork: true       # sem isolamento de rede
  containers:
    - name: app
      securityContext:
        runAsUser: 0      # root
        privileged: true  # capabilities completas
        allowPrivilegeEscalation: true
```

```yaml
# ✅ CORRETO
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

### Secrets em Variáveis de Ambiente

```yaml
# ❌ VULNERÁVEL — segredo hardcoded em env
env:
  - name: DB_PASSWORD
    value: "supersecreto123"

# ✅ CORRETO — referência a Kubernetes Secret
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: db-credentials
        key: password
```

---

## 🏗️ Terraform / AWS — Vulnerabilidades

### IAM com Permissões Wildcard

```hcl
# ❌ CRÍTICO — permissão total na conta AWS
resource "aws_iam_policy" "app_policy" {
  policy = jsonencode({
    Statement = [{
      Action   = "*"       # tudo
      Resource = "*"       # em tudo
      Effect   = "Allow"
    }]
  })
}
```

### S3 Bucket Público

```hcl
# ❌ CRÍTICO — bucket publicamente legível/gravável
resource "aws_s3_bucket" "data" {
  acl = "public-read-write"
}

# ✅ CORRETO
resource "aws_s3_bucket" "data" {
  # sem ACL pública
}
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### Security Group Aberto

```hcl
# ❌ CRÍTICO — SSH e RDP abertos para a internet
resource "aws_security_group_rule" "ssh_open" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  # internet inteira
}
```

### Output Sensível sem `sensitive`

```hcl
# ❌ VULNERÁVEL — exposição em logs do Terraform
output "db_password" {
  value = aws_db_instance.main.password
  # sensitive = true  ← faltou
}
```

---

## 🔗 Chain Exploits

```
RCE na app + container privileged → Fuga para host → Comprometimento total
RCE na app + ENV com AWS keys → Comprometimento da conta cloud
S3 público + .env no bucket → Credenciais expostas → Acesso ao banco
IAM wildcard comprometido → Exfiltração de toda infra
```

---

## 📌 Referências
- [[CI-CD Pipeline Attack Surface]]
- [[Command Injection & RCE]]
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NSA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
