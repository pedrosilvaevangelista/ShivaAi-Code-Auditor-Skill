# IaC Security — Terraform, K8s & Docker

**Tags:** #high #iac #terraform #kubernetes #docker #cloud #misconfiguration
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
capabilities:
  add: ["SYS_ADMIN"]
```

---

## 💣 Attack Category 1: IAM Over-Privilege (Terraform)

The most common IaC flaw. Assigning `AdministratorAccess` or `*` actions to a service role.

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

**Static Detection:** Trace `aws_iam_policy` and `aws_iam_role_policy` resources. Flag any use of `*` in `Action` or `Resource`.

---

## 💣 Attack Category 2: Kubernetes Namespace Escape

Misconfigured pods can escape the container and take over the worker node.

**Vulnerable Patterns (K8s YAML):**
- `privileged: true`: Pod has root access to the host kernel.
- `hostPath: /`: Mounts the host root filesystem into the pod.
- `hostNetwork: true`: Pod shares the host's network namespace (bypasses K8s NetworkPolicies).

**Static Detection:** Search for these flags in `Deployment`, `Pod`, or `StatefulSet` manifests.

---

## 💣 Attack Category 3: Publicly Exposed Data Stores

**Terraform:**
```hcl
resource "aws_s3_bucket" "b" {
  acl = "public-read-write" # CRITICAL FAIL
}
```

**Security Groups:**
```hcl
resource "aws_security_group" "allow_all" {
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # Exposure to the entire internet
  }
}
```

---

## 🛡️ Fix & Hardening

1. **Principle of Least Privilege:** Use specific actions (e.g., `s3:GetObject`) instead of `*`.
2. **Network Isolation:** Use Security Groups to allow traffic only from known sources (load balancers, VPNs).
3. **Non-Root Containers:** Ensure pods run with `runAsNonRoot: true`.
4. **Secrets Management:** Use `vault_generic_secret` or `aws_secretsmanager_secret` instead of hardcoding values in variables.

---

## 🔗 Chain Exploits

```
App RCE + Over-privileged IAM Role  Full Cloud Account takeover (IMDSv2 Pivot)
K8s Pod RCE + privileged: true  Host node takeover + Access to all other Pods
Public S3 Bucket + sensitive logs  Data breach without needing a code exploit
```

---

## 📌 References
- [Terraform Security Best Practices](https://www.terraform.io/docs/cloud/plan/security.html)
- [Kubernetes Security Checklist](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [[container-escape-protocol]]
