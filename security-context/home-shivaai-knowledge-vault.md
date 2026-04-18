# ShivaAi Security Knowledge Vault

> **Motor de Auditoria Cibernética Sênior**
> *Conhecimento ancorado. Sem especulação. Sem scanner.*

---

## Índice da Vault

### Injeção & Execução Remota
- [[sql-injection-sqli]]
- [[command-injection-rce]]
- [[ssti-server-side-template-injection]]
- [[xml-external-entity-xxe]]
- [[ldap-injection]]
- [[nosql-injection]]
- [[crlf-injection]]
- [[second-order-injection]]

### Autenticação & Sessão
- [[jwt-algorithm-confusion-ataques]]
- [[autenticacao-gestao-de-sessao]]
- [[oauth-2.0-saml-ataques-de-protocolo]]
- [[deserializacao-insegura]]

### Controle de Acesso
- [[idor-bola-broken-object-level-authorization]]
- [[mass-assignment]]
- [[business-logic-flaws]]
- [[ssrf-server-side-request-forgery]]
- [[path-traversal-lfi]]

### Frontend & Client-Side
- [[xss-cross-site-scripting]]
- [[dom-based-xss-postmessage]]
- [[cors-misconfiguration]]
- [[csrf-websocket-hijacking-cswsh]]
- [[open-redirect]]
- [[prototype-pollution]]

### Infraestrutura & Pipeline
- [[iac-security-docker-kubernetes-terraform]]
- [[ci-cd-pipeline-attack-surface]]
- [[http-security-headers]]
- [[http-request-smuggling]]
- [[analise-de-dependencias-por-cve]]

### Criptografia
- [[criptografia-falhas-sistematicas]]
- [[hashing-inseguro-de-senhas]]

### APIs & Protocolos Modernos
- [[graphql-superficie-de-ataque]]
- [[race-condition-toctou]]
- [[unrestricted-file-upload]]
- [[redos-regex-denial-of-service]]

### Metodologia & Templates
- [[pei-protocolo-de-investigacao-exploratoria]]
- [[matriz-de-severidade]]
- [[template-de-finding]]
- [[taint-analysis-cognitivo]]
- [[chain-exploit-efeito-borboleta]]

---

## Princípios do Auditor Paranoico

> *"Vulnerabilidades de alto impacto habitam onde o desenvolvedor sentiu medo."*

1. **Ceticismo Contínuo** — Todo filtro é falso até prova em contrário
2. **Âncora Obrigatória** — Toda claim precisa de arquivo + linha exata
3. **Exaustão Total** — Nenhum arquivo é irrelevante
4. **Psicanálise do Código** — Leia as "cicatrizes" do desenvolvedor
5. **Chain Exploit** — Um "Low" pode virar "Critical" encadeado

---

## Atualizações da Vault

| Data | Nota Criada/Atualizada | Motivo |
|---|---|---|
| 2026-04-17 | Vault criada | Inicialização completa da base de conhecimento |

---

*Tags: #vault-index #shiva-ai #security*
