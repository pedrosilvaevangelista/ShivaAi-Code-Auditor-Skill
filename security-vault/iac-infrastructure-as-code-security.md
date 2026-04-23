# IaC Security — Terraform, K8s & Docker

**Tags:** #high #iac #terraform #kubernetes #docker #cloud #misconfiguration #statefile
**OWASP:** A05:2021 Security Misconfiguration
**CVSS Base:** 7.5 (High) — 9.1 (Critical if allowing full Cloud Provider takeover)

---

## 📖 What it is

Infrastructure-as-Code (IaC) allows defining hardware and networking via code. Security failures in IaC lead to "Hostile Infrastructure" where the application might be secure, but the environment exposing it is wide open.

---

## 🔍 `grep_search` Tactics

```
resource "aws_iam_role"
privileged: true
hostNetwork: true
allow_all
0.0.0.0/0
acl = "public-read"
runAsUser: 0
terraform.tfstate
ARG
cluster-admin
```

---

## 💣 Attack Category 1: IAM Over-Privilege (Terraform)
Assigning `AdministratorAccess` or `*` actions to a service role.
**Vulnerable Pattern (Terraform):**
```hcl
resource "aws_iam_role_policy" "example" {
  policy = jsonencode({
    Statement = [{
      Action   = "*"
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}
```
**Static Detection:** Trace `aws_iam_policy` and flag any use of `*` in `Action` or `Resource`.

## 💣 Attack Category 2: Kubernetes Namespace Escape & RBAC Abuse
Misconfigured pods can escape the container and take over the worker node, or RBAC grants too much power.
**Vulnerable Patterns (K8s YAML):**
- `privileged: true`: Pod has root access to the host kernel.
- `hostPath: /`: Mounts the host root filesystem into the pod.
- `hostNetwork: true`: Pod shares the host's network namespace.
- **RBAC:** A `ClusterRoleBinding` granting `cluster-admin` to the `default` ServiceAccount.

## 💣 Attack Category 3: Publicly Exposed Data Stores
**Terraform:**
```hcl
resource "aws_s3_bucket" "b" {
  acl = "public-read-write" # CRITICAL FAIL
}
```
**Security Groups:**
`cidr_blocks = ["0.0.0.0/0"]` on internal ports (e.g., 3306, 5432).

## 💣 Attack Category 4: Terraform State File Exposure
**How it works:** Terraform stores the state of the infrastructure in a `terraform.tfstate` file. This file contains **plaintext secrets** (database passwords, API keys) even if they were passed as variables.
**Attack:** If the state file is committed to Git, or stored in an unencrypted/public S3 bucket without strict IAM access, attackers can extract all infrastructure secrets.

## 💣 Attack Category 5: Docker Build Args vs Env Vars
**How it works:** Developers pass secrets to Docker during the build process using `ARG`.
**Attack:** Arguments passed via `ARG` and used in `RUN` commands are saved in the Docker image history. Anyone with access to the image can run `docker history --no-trunc image_name` and view the plaintext secrets.
**Fix:** Use Docker BuildKit secrets (`--mount=type=secret`).

---

## 🛡️ Fix & Hardening
1. **Principle of Least Privilege:** Use specific actions (e.g., `s3:GetObject`) instead of `*`.
2. **Network Isolation:** Use Security Groups to allow traffic only from known sources.
3. **Non-Root Containers:** Ensure pods run with `runAsNonRoot: true`.
4. **State File Encryption:** Always use remote state backends (S3 + DynamoDB for locking) with Server-Side Encryption (SSE) and strict IAM policies. Never commit `.tfstate`.

---

## 🔗 Chain Exploits
```
App RCE + Over-privileged IAM Role ➔ Full Cloud Account takeover (IMDS Pivot)
K8s Pod RCE + privileged: true ➔ Host node takeover + Access to all other Pods
Public S3 Bucket + terraform.tfstate ➔ Total Infrastructure Compromise
```
