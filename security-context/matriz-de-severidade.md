# Matriz de Severidade

**Tags:** #metodologia #severidade #cvss #classificacao
**Tipo:** Referência de classificação

---

## 📊 Matriz Principal

| Severidade | Emoji | Critério Real | CVSS Range |
|---|---|---|---|
| **Crítico** | 🔴 | RCE não-autenticado, SQLi com dump total, LFIRCE Chain, Deserialization RCE | 9.010.0 |
| **Alto** | 🟠 | SQLi autenticado, Upload de Webshell, Bypass completo de Auth, SSRF interno, JWT Confusion | 7.08.9 |
| **Médio** | 🟡 | XSS Stored, IDOR com acesso a dados de terceiros, Second-Order Injection, CORS crítico | 4.06.9 |
| **Baixo** | 🔵 | XSS Refletido sem estabilidade, Information Disclosure sem impacto direto, Open Redirect isolado | 1.03.9 |
| **Info** |  | Configurações que aumentam superfície de ataque, mas não exploráveis sozinhas | 0.00.9 |

---

## ️ Regra Crítica de Reclassificação por Chain

> **Todo "Baixo" e "Info" deve ser avaliado no contexto de chain exploit.**
> Se combinado com outra falha eleva a severidade, reclassificar e documentar a cadeia.

### Exemplos de Reclassificação

| Finding Isolado | Severidade Original | Com Chain | Nova Severidade |
|---|---|---|---|
| Open Redirect | 🔵 Baixo | + OAuth redirect_uri | 🟠 Alto (token theft) |
| XSS Refletido | 🔵 Baixo | + Ausência de CSP | 🟡 Médio  🟠 Alto |
| Stack Trace com query SQL |  Info | + SQLi no mesmo endpoint | 🔴 Crítico |
| CRLF Injection | 🔵 Baixo | + Cache Poisoning | 🟠 Alto (XSS persistente) |
| CORS dinâmico | 🟡 Médio | + `credentials: true` | 🟠 Alto |
| WebSocket sem Origin check | 🟡 Médio | + Comandos admin no WS | 🔴 Crítico |
| Info Disclosure em logs |  Info | + SQLi + Log leak | 🔴 Crítico |
| Mass Assignment | 🟡 Médio | + role=admin aceito | 🔴 Crítico |

---

## 🏷️ Status de um Finding

| Status | Significado |
|---|---|
| Confirmado por Análise Estática | Código vulnerável localizado e ancorado, sem execução |
| Requer Validação de Runtime | Complexidade dinâmica impede confirmação apenas por SAST |
| Confirmado por Exploração Ativa | PoC executado com sucesso, evidência de runtime obtida |
| Falso Positivo | Análise inicial apontou risco, mas leitura aprofundada confirmou mitigação |

---

## 📐 CVSS 3.1  Scores de Referência por Vulnerabilidade

| Vulnerabilidade | Score | Vetor CVSS |
|---|---|---|
| RCE não-autenticado remoto | 10.0 | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H |
| SQLi  dump total sem auth | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| SSRF  Cloud Metadata | 8.6 | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N |
| JWT Algorithm Confusion | 8.1 | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H |
| XSS Stored + Admin Panel | 8.0 | AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N |
| IDOR/BOLA autenticado | 7.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| Path Traversal  chave privada | 7.5 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| XXE com OOB exfiltração | 7.4 | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N |
| XSS Stored (usuário casual) | 6.1 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| Open Redirect isolado | 3.1 | AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N |

---

## 🎯 Critérios por Categoria

### 🔴 Crítico  Ação Imediata (24h)
- Permite acesso root/admin sem autenticação
- Permite dump completo do banco
- Permite execução de código no servidor
- Permite comprometimento de infraestrutura (cloud credentials)

### 🟠 Alto  Correção Prioritária (1 semana)
- Permite escalonamento de privilégios com autenticação
- Permite acesso não-autorizado a dados sensíveis de outros usuários
- Permite bypass de autenticação em funcionalidades críticas
- Permite pivot para rede interna

### 🟡 Médio  Planejamento no Sprint (1 mês)
- Permite roubo de dados com interação do usuário
- Permite acesso não-autorizado a dados próprios do usuário
- Permite manipulação de estado da aplicação

### 🔵 Baixo  Backlog de Segurança
- Requer condições muito específicas
- Impacto limitado mesmo se explorado

---

## 📌 Referências
- [[template-de-finding]]
- [[chain-exploit-efeito-borboleta]]
- [[pei-protocolo-de-investigacao-exploratoria]]
