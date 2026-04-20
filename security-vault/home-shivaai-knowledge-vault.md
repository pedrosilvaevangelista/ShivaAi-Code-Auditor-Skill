# ShivaAi Security Knowledge Vault

> **Senior Cyber Audit Engine**
> *Anchored knowledge. No speculation. No scanner.*

---

## Vault Index

### Injection & Remote Execution
- [[sql-injection-sqli]]
- [[command-injection-rce]]
- [[ssti-server-side-template-injection]]
- [[xml-external-entity-xxe]]
- [[ldap-injection]]
- [[nosql-injection]]
- [[crlf-injection]]
- [[second-order-injection]]

### Authentication & Session
- [[jwt-algorithm-confusion-attacks]]
- [[authentication-session-management]]
- [[oauth-2.0-saml-protocol-attacks]]
- [[insecure-deserialization-protocol]]

### Access Control
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

### Infrastructure & Pipeline
- [[iac-security-docker-kubernetes-terraform]]
- [[ci-cd-pipeline-attack-surface]]
- [[http-security-headers]]
- [[http-request-smuggling]]
- [[dependency-analysis-cve]]
- [[supply-chain-security]]
- [[log-injection-tampering]]

### Cryptography
- [[systemic-cryptography-flaws]]
- [[insecure-password-hashing]]
- [[side-channel-timing-attacks]]

### APIs & Modern Protocols
- [[graphql-attack-surface]]
- [[race-condition-toctou]]
- [[unrestricted-file-upload]]
- [[redos-regex-denial-of-service]]
- [[grpc-protobuf-attack-surface]]
- [[api-semantic-desync]]

### AI & Emerging Tech
- [[llm-ai-security]]
- [[web3-dapp-security]]
- [[iot-embedded-shadow-logic]]

### Methodology & Templates
- [[eip-exploratory-investigation-protocol]]
- [[severity-matrix]]
- [[finding-template]]
- [[cognitive-taint-analysis]]
- [[chain-exploit-butterfly-effect]]

---

## Paranoid Auditor Principles

> *"High-impact vulnerabilities reside where the developer felt fear."*

1. **Continuous Skepticism** — Every filter is false until proven otherwise.
2. **Mandatory Anchor** — Every claim needs the exact file + line.
3. **Total Exhaustion** — No file is irrelevant.
4. **Code Psychoanalysis** — Read the developer's "scars".
5. **Chain Exploit** — A "Low" can become "Critical" through chaining.

---

## Vault Updates

| Date | Note Created/Updated | Reason |
|---|---|---|
| 2026-04-17 | Vault Created | Full initialization of the knowledge base. |
| 2026-04-20 | Vault Hardening | Upgrade v1.60: Added AI Security, Supply Chain, and missing tactical pillars. |
| 2026-04-20 | Pillar Evolution | Upgrade v1.70: Focus on Cryptographic Side-Channels, API Desync, and Deep Tech (IoT/Web3). |
| 2026-04-20 | Depth Hardening | Upgrade v1.80: Rule of Depth applied — insecure-deserialization, pii-data-leakage, dom-clobbering, json-hijacking fully remastered to elite level. Pillars 73 (Clickjacking) and 74 (HTTP/2 Rapid Reset) added. |

---

*Tags: #vault-index #shiva-ai #security*
