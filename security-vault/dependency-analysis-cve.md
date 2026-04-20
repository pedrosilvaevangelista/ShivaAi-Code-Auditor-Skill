# Dependency Analysis by CVE

**Tags:** #critical #cve #dependencies #supply-chain #vulnerable-versions
**OWASP:** A06:2021 Vulnerable and Outdated Components
**CVSS Base:** Variable → up to 10.0 (Log4Shell)

---

## 📖 What is it

Third-party dependencies with critical CVEs are vulnerabilities independent of the application's code quality. They must be audited **before** any- Typosquatting of common libraries.

### [NEW] Lockfile Poisoning (pnpm/yarn)
**How it works:** Attacker modifies `pnpm-lock.yaml` or `yarn.lock` to point a trusted dependency to a malicious version or a different registry entirely, without changing `package.json`.
**Audit:** Check for mismatching hashes in lockfiles.

---

## 🔍 Files to Read in Phase 0.5

```
package.json           Node.js / NPM
package-lock.json      exact transitive versions (NPM)
yarn.lock              Yarn
composer.json          PHP
composer.lock          exact versions (PHP)
requirements.txt       Python pip
Pipfile.lock           Python Pipenv
poetry.lock            Python Poetry
pom.xml                Java Maven
build.gradle           Java Gradle
Gemfile                Ruby
Gemfile.lock           exact versions (Ruby)
go.sum                 Go modules
Cargo.toml             Rust
nuget.packages         .NET
packages.config        .NET (legacy)
```

---

## 🔴 High-Priority Critical CVEs — Check by Version

### Java

| Component | Vulnerable Version | CVE | Impact |
|---|---|---|---|
| `log4j-core` | `< 2.15.0` | CVE-2021-44228 | **Log4Shell — Unauthenticated RCE** |
| `log4j-core` | `< 2.17.0` | CVE-2021-45046 | RCE variant (initial fix bypass) |
| `spring-core` | `< 5.3.18` | CVE-2022-22965 | **Spring4Shell — RCE** |
| `spring-webmvc` | `< 5.3.18` | CVE-2022-22965 | Spring4Shell |
| `struts2` | `< 2.5.33` | CVE-2023-50164 | Recurring historical RCE |
| `jackson-databind` | `< 2.9.10` | CVE-2019-14379 | Deserialization RCE |
| `commons-collections` | `< 3.2.2` | CVE-2015-6420 | Java Deserialization gadget chain |

### JavaScript / Node.js

| Component | Vulnerable Version | CVE | Impact |
|---|---|---|---|
| `lodash` | `< 4.17.21` | CVE-2021-23337 | Prototype Pollution → RCE |
| `lodash` | `< 4.17.20` | CVE-2020-8203 | Prototype Pollution |
| `node-serialize` | Any | CVE-2017-5941 | **Deserialization RCE** |
| `express` | `< 4.18.2` | CVE-2022-24999 | ReDoS |
| `jsonwebtoken` | `< 9.0.0` | CVE-2022-23529 | Remote Code Execution |
| `axios` | `< 1.6.0` | CVE-2023-45857 | CSRF + SSRF |
| `semver` | `< 7.5.2` | CVE-2022-25883 | ReDoS |

### Python

| Component | Vulnerable Version | CVE | Impact |
|---|---|---|---|
| `PyYAML` | `< 6.0` | CVE-2017-18342 | `yaml.load()` without Loader = RCE |
| `Pillow` | `< 9.3.0` | CVE-2022-45198 | Buffer overflow → RCE |
| `Django` | `< 3.2.15` | CVE-2022-36359 | Reflected XSS |
| `Flask` | `< 2.3.2` | CVE-2023-30861 | Session cookie bypass |
| `requests` | `< 2.31.0` | CVE-2023-32681 | Header injection |
| `cryptography` | `< 41.0.0` | CVE-2023-2650 | DoS |

### PHP

| Component | Vulnerable Version | CVE | Impact |
|---|---|---|---|
| `laravel/framework` | `< 9.x` (check changelog) | CVE-2021-21263 | Mass Assignment |
| `symfony/http-kernel` | `< 5.4.3` | CVE-2022-24894 | Cookie injection |
| `phpdocumentor/reflection-docblock` | `< 5.3.0` | CVE-2022-24828 | RCE |

### Ruby

| Component | Vulnerable Version | CVE | Impact |
|---|---|---|---|
| `rails` | `< 7.0.3` | CVE-2022-23633 | CSRF bypass |
| `nokogiri` | `< 1.13.4` | CVE-2022-24836 | RCE via XXE |

### .NET

| Component | Vulnerable Version | CVE | Impact |
|---|---|---|---|
| `Newtonsoft.Json` | `< 13.0.1` | CVE-2021-42159 | ReDoS |
| `Microsoft.AspNetCore` | Check specific version | CVE-2022-34716 | Information Disclosure |

---

## 🧪 Dependency Analysis Script

```python
# .tmp/check_deps.py — DISCARD AFTER USE
import json, re

# Check package.json
try:
    with open('package.json') as f:
        pkg = json.load(f)
    
    all_deps = {}
    all_deps.update(pkg.get('dependencies', {}))
    all_deps.update(pkg.get('devDependencies', {}))
    
    CRITICAL_PACKAGES = {
        'lodash': ('4.17.21', 'CVE-2021-23337 — Prototype Pollution — RCE'),
        'jsonwebtoken': ('9.0.0', 'CVE-2022-23529 — RCE'),
        'node-serialize': ('999.0.0', 'CVE-2017-5941 — Deserialization RCE (ANY VERSION)'),
        'axios': ('1.6.0', 'CVE-2023-45857 — CSRF/SSRF'),
        'semver': ('7.5.2', 'CVE-2022-25883 — ReDoS'),
    }
    
    print("=== NPM Dependency Audit ===")
    for pkg_name, (min_safe, desc) in CRITICAL_PACKAGES.items():
        if pkg_name in all_deps:
            version = all_deps[pkg_name].lstrip('^~>=')
            print(f"[FOUND] {pkg_name}@{version}")
            print(f"  Min safe: {min_safe} | {desc}")
except FileNotFoundError:
    print("[skip] package.json not found")

# Check requirements.txt
try:
    with open('requirements.txt') as f:
        reqs = f.readlines()
    
    CRITICAL_PYTHON = {
        'pyyaml': ('6.0', 'CVE-2017-18342 — yaml.load() RCE'),
        'django': ('3.2.15', 'CVE-2022-36359 — XSS'),
        'flask': ('2.3.2', 'CVE-2023-30861 — Session bypass'),
        'requests': ('2.31.0', 'CVE-2023-32681 — Header injection'),
    }
    
    print("\n=== Python Dependency Audit ===")
    for req in reqs:
        req = req.strip().lower()
        for pkg_name, (min_safe, desc) in CRITICAL_PYTHON.items():
            if req.startswith(pkg_name):
                print(f"[FOUND] {req}")
                print(f"  Min safe: {min_safe} | {desc}")
except FileNotFoundError:
    print("[skip] requirements.txt not found")
```

---

## 🛡️ Fix

```bash
# Node.js — update vulnerable dependencies
npm audit fix
npm audit fix --force  # ⚠️ may cause breaking changes

# Check vulnerabilities without updating
npm audit

# Python
pip install --upgrade safety
safety check -r requirements.txt

# PHP
composer audit
```

---

## 🔗 Chain Exploits

```
log4j < 2.15.0 → any log with user input → Log4Shell RCE
Python PyYAML < 6.0 + yaml.load(input) → direct RCE
lodash < 4.17.21 + merge of user object → Prototype Pollution → Auth bypass
Vulnerable jackson-databind + endpoint that deserializes JSON → RCE via gadget
```

---

## 📌 References
- [[insecure-deserialization]]
- [[prototype-pollution]]
- [[eip-exploratory-investigation-protocol]]
- [NVD National Vulnerability Database](https://nvd.nist.gov/)
- [Snyk Vulnerability DB](https://security.snyk.io/)
- [GitHub Advisory Database](https://github.com/advisories)