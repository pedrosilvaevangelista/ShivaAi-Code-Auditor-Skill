# Severity Matrix

**Tags:** #methodology #severity #triage #risk
**Type:** Triage standard — *not a vulnerability*

---

## 📖 Definition

The ShivaAi engine uses a unified risk matrix based on **Technical Impact** + **Exploitation Effort** + **Business Context**.

Every finding must be classified according to the "Worst Case Scenario" of a plausible attack chain.

---

## 🔝 Severity Levels

| Severity | Technical Criterion | Real-World Impact |
|---|---|---|
| **Critical** | Unauthenticated RCE, SQLi with full dump, LFI→RCE Chain, Mass Account Takeover. | Full compromise of the server or the entire database. |
| **High** | Authenticated SQLi, Persistent XSS in Admin, Full Auth Bypass, Internal SSRF (Cloud Metadata). | Direct compromise of administrative users or internal server infrastructure. |
| **Medium** | Stored XSS, IDOR with third-party data access, Insecure Deserialization (no RCE yet), PII leakage. | Exposure of sensitive user data or subversion of authorization for specific accounts. |
| **Low** | Reflected XSS without stability, Open Redirect, CRLF Injection, Insecure Cache. | Technical flaw with limited impact or requiring complex social engineering. |
| **Info** | Verbose Stack Trace, Version Disclosure, Missing Security Headers, Weak Ciphers. | Exposure of technical info that assists in reconnaissance or increases the attack surface. |

---

## 🔄 Dynamic Reclassification (The Chain Rule)

A vulnerability's severity is not static. It **must** be promoted if it is part of a verified attack chain:

- **Info + High = Critical:** A verbose stack trace (Info) that provides the exact query for a blind SQLi (High) makes the SQLi **Critical**.
- **Low + Medium = High:** An Open Redirect (Low) that allows bypassing a domain whitelist for an SSRF (Medium) makes the SSRF **High**.
- **Info + Medium = High:** Version disclosure of a library (Info) with a known high-severity CVE (Pillar 14).

> [!IMPORTANT]
> **Audit Principle:** Never ignore a "Low". Analyze it as a potential first link in an [[chain-exploit-butterfly-effect]].

---

## 🛠️ Remediation Priority

1. **Critical:** Immediate Fix (24-48h). Stop production deployment if possible.
2. **High:** Prioritize in next sprint.
3. **Medium:** Fix within 30 days.
4. **Low/Info:** Best practices; fix as technical debt.

---

## 📌 References
- [[finding-template]]
- [[chain-exploit-butterfly-effect]]
- [[eip-exploratory-investigation-protocol]]
