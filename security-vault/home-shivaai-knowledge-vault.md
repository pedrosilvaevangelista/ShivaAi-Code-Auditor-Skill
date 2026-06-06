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
- [[account-pre-takeover]]

### Access Control
- [[idor-bola-broken-object-level-authorization]]
- [[bfla-broken-function-level-authorization]]
- [[mass-assignment]]
- [[business-logic-flaws]]
- [[business-logic-numeric-overflow]]
- [[ssrf-server-side-request-forgery]]
- [[path-traversal-lfi]]

### Frontend & Client-Side
- [[xss-cross-site-scripting]]
- [[dom-based-xss-postmessage]]
- [[cors-misconfiguration]]
- [[csrf-websocket-hijacking-cswsh]]
- [[open-redirect]]
- [[prototype-pollution]]
- [[clickjacking-ui-redressing]]

### Infrastructure & Pipeline
- [[iac-security-docker-kubernetes-terraform]]
- [[ci-cd-pipeline-attack-surface]]
- [[security-misconfiguration-default-debug]]
- [[http-security-headers]]
- [[http-request-smuggling]]
- [[dependency-analysis-cve]]
- [[supply-chain-security]]
- [[log-injection-tampering]]
- [[subdomain-takeover]]

### Cryptography
- [[systemic-cryptography-flaws]]
- [[insecure-password-hashing]]
- [[side-channel-timing-attacks]]

### APIs & Modern Protocols
- [[graphql-attack-surface]]
- [[race-condition-toctou]]
- [[unrestricted-file-upload]]
- [[anti-automation-bot-protection]]
- [[redos-regex-denial-of-service]]
- [[grpc-protobuf-attack-surface]]
- [[api-semantic-desync]]

### AI & Emerging Tech
- [[llm-ai-security]]
- [[web3-dapp-security]]
- [[iot-embedded-shadow-logic]]

### Error Handling, Resilience & Memory
- [[mishandling-exceptional-conditions]]
- [[application-resilience-dos]]
- [[memory-management-failures]]

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
| 2026-04-20 | Depth Hardening | Upgrade v1.90: side-channel-timing, second-order-injection, waf-evasion remastered to elite level. Pillars 75 (Subdomain Takeover) and 76 (Clickjacking Full Protocol) anchored. |
| 2026-04-20 | **MILESTONE v2.0** | Hostile Architecture Synthesis: path-traversal-lfi, unrestricted-file-upload, supply-chain-security, cognitive-taint-analysis remastered to elite level. Pillars 77 (Account Pre-Takeover) and 78 (Business Logic Numeric Overflow) added. Engine reaches 78-pillar doctrine with elite-depth vault. |
| 2026-06-06 | OWASP 2025 Sync | Upgrade v2.1: Integrated A01:2025 Broken Access Control. Created Pillar 79 (BFLA & Force Browsing) and updated IDOR/BOLA to cover exact parameter tampering scenarios from OWASP. |
| 2026-06-06 | OWASP 2025 Sync | Upgrade v2.2: Integrated A02:2025 Security Misconfiguration. Created Pillar 80 (Security Misconfiguration & Default Settings) to cover CWE-489 (Debug), CWE-16 (Defaults), CWE-548 (Directory Listing) and S3 buckets. |
| 2026-06-06 | OWASP 2025 Sync | Upgrade v2.3: Integrated A03:2025 Software Supply Chain Failures. Deepened Pillar 50 (Supply Chain Security) with self-propagating worm tactics (Shai-Hulud) and updated mapping in Dependency Analysis (Pillar 16). |
| 2026-06-06 | OWASP 2025 Sync | Upgrade v2.4: Integrated A04:2025 Cryptographic Failures. Added Post Quantum Cryptography (PQC) readiness checks to Systemic Cryptography Flaws, and re-mapped Password Hashing. |
| 2026-06-06 | OWASP 2025 Sync | Upgrade v2.5: Integrated A05:2025 Injection. Re-mapped SQLi, Command Injection, and XSS to A05. Added specific HQL (Hibernate Query Language) ORM injection scenarios to the SQLi pillar based on OWASP 2025 focus areas. |
| 2026-06-06 | OWASP 2025 Sync | Upgrade v2.6: Integrated A06:2025 Insecure Design. Re-mapped Business Logic Flaws. Created Pillar 81 (Unrestricted File Upload) to cover CWE-434 and Pillar 82 (Anti-Automation & Rate Limiting) to cover CWE-799 and scalping bots. |
| 2026-06-06 | OWASP 2025 Sync | Upgrade v2.7: Integrated A07:2025 Authentication Failures. Re-mapped Authentication & Session Management. Added tactical scenarios for Single Logout (SLO) failures and Hybrid Credential Stuffing (Password Spraying). |
| 2026-06-06 | OWASP 2025 Sync | Upgrade v2.8: Integrated A08:2025 Software or Data Integrity Failures and A09:2025 Security Logging & Alerting Failures. Re-mapped Insecure Deserialization, Prototype Pollution, and Log Injection. Added tactical scenarios for Honeytokens, Alerting failures, and React/Spring Boot deserialization chains. |
| 2026-06-06 | **MILESTONE v3.0** | Full OWASP Top 10:2025 Sync Complete. Integrated A10, X01, X02, X03. Created Pillars 83 (Mishandling Exceptional Conditions), 84 (Application Resilience & DoS), 85 (Memory Management Failures). Updated LLM Security with Vibe Coding (X03). Engine reaches **85-pillar doctrine** — fully synchronized with OWASP Top 10:2025 and all "Next Steps" categories. |

---

*Tags: #vault-index #shiva-ai #security*
