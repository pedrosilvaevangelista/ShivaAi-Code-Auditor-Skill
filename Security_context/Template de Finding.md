# Template de Finding

**Tags:** #template #relatorio #metodologia
**Tipo:** Template de uso — copiar para cada vulnerability encontrada

---

## 📋 Estrutura Obrigatória de Each Finding

```markdown
---
## [ID] [SEVERIDADE] — [Nome do Vetor] | CVSS: [X.X]
**Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
**OWASP:** A0X:2021 — [Nome da Categoria]
**Status:** Confirmado por Análise Estática | Confirmado por Exploração Ativa

### Evidência Ancorada
**Arquivo:** `path/to/file.ext` | **Linhas:** XX-YY
```[linguagem]
[código vulnerável EXATO lido, com as linhas exatas]
```

### Narrativa de Ataque
[Descrição em prosa de como o atacante explora a vulnerabilidade.
Deve incluir: quem é o atacante (autenticado/não), qual endpoint,
qual payload, qual o resultado imediato.]

### Impacto Real

#### 💥 Impacto Técnico
[O que o atacante CONSEGUE fazer tecnicamente: RCE, dump de banco,
leitura de arquivos, escalação de privilégios. Seja específico ao contexto.]

#### 💰 Impacto de Negócio
[Consequências financeiras, legais e reputacionais: multas LGPD/GDPR,
perda de confiança de clientes, exposição de propriedade intelectual,
interrupção de operações, custos de incident response.]

#### 🔗 Superfície de Exposição
[Quem pode explorar: não-autenticado via internet? Autenticado?
Requer acesso à rede interna? Trivialidade do ataque (script kiddie vs APT)?
Existe exploit público ou PoC automatizável?]

### Validação Manual
**Pré-requisitos:** [ferramentas necessárias: Burp Suite, curl, browser, etc.]

1. [Passo 1 — preparação do ambiente/ferramenta]
2. [Passo 2 — payload exato a ser inserido e onde]
3. [Passo 3 — o que observar como resultado positivo]
4. [Passo 4 — evidência esperada: screenshot, output, resposta HTTP]

**Resultado Esperado:** [descrição precisa do que constitui confirmação]
**Ferramentas Alternativas:** [sqlmap, Burp Intruder, browser DevTools, curl, etc.]

### Prova de Conceito (Script Executável)
```python
# PoC gerado pelo motor — executável diretamente
import requests

TARGET = "http://target.com"

# [script real baseado no código lido]
r = requests.post(f"{TARGET}/endpoint", data={"param": "payload"})
print(r.status_code, r.text[:500])
```

### Código Corrigido (Patch Contextual)
```diff
- [linha vulnerável original]
+ [linha corrigida]
```
*Justificativa da correção: [explicação da causa-raiz, não apenas do sintoma]*

### Impacto em Cadeia
Se combinado com [[outro-finding]]: escala de [Severidade A] para [Severidade B].
---
```

---

## 📋 Encerramento Obrigatório do Relatório

```markdown
## Matriz de Priorização — Risco × Esforço de Correção

| Finding | Severidade | Esforço de Fix | ROI de Segurança |
|---|---|---|---|
| [ID-01] | 🔴 Crítico | Baixo (30min) | ⭐⭐⭐⭐⭐ Corrija hoje |
| [ID-02] | 🟠 Alto | Médio (2h) | ⭐⭐⭐⭐ Alta prioridade |
| [ID-03] | 🟡 Médio | Alto (1 Sprint) | ⭐⭐⭐ Planeje |

## Narrativa de Comprometimento Total (Kill Chain)
[História em prosa de como um atacante real encadearia os findings para
comprometimento total — do primeiro contato até RCE ou exfiltração completa.]
```

---

## 🎯 IDs de Finding — Convenção

```
CRIT-01, CRIT-02  → Crítico (RCE não-autenticado, SQLi com dump total)
HIGH-01, HIGH-02  → Alto (SQLi autenticado, Upload webshell, Auth bypass)
MED-01, MED-02    → Médio (XSS Stored, IDOR, Second-Order)
LOW-01, LOW-02    → Baixo (XSS Refletido instável, Info Disclosure)
INFO-01, INFO-02  → Informativo (Surface amplificadora, não direto)
```

---

## 📊 Vector String CVSS 3.1 — Referência Rápida

```
AV: Attack Vector    → N=Network, A=Adjacent, L=Local, P=Physical
AC: Attack Complexity → L=Low, H=High
PR: Privileges Required → N=None, L=Low, H=High
UI: User Interaction → N=None, R=Required
S:  Scope            → U=Unchanged, C=Changed
C:  Confidentiality  → N=None, L=Low, H=High
I:  Integrity        → N=None, L=Low, H=High
A:  Availability     → N=None, L=Low, H=High

Exemplo RCE não-autenticado:
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0 Crítico
```

---

## 📌 Referências
- [[Matriz de Severidade]]
- [[PEI — Protocolo de Investigação Exploratória]]
- [[Chain Exploit — Efeito Borboleta]]
