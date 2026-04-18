# Finding Template

**Tags:** #template #reporting #quality
**Type:** Layout reference — *not a vulnerability*

---

## 🛠️ Finding Structure

Every finding in the `reports/` folder must follow this exact structure to ensure professional rigor and clear communication with developers.

---

### [ID] Name of the Vulnerability

**Severity:** [Critical | High | Medium | Low | Info]  
**Category:** [e.g., Injection, Broken Access Control, etc.]  
**Anchors:** [file-basename.ext:LineNumber] — *Mandatory*  
**Status:** [Confirmed by Static Analysis | Confirmed by Active Exploitation]

#### 🔍 Description
Clear and concise technical explanation of the vulnerability. How it works in the context of this specific code. Use code snippets if necessary.

#### 🔗 Attack Chain (Butterfly Effect)
If this finding is linked to others, describe the flow here. Ex: "This Open Redirect allows bypassing the SSRF whitelist in [[finding-02]]."

#### 💣 Proof of Concept (PoC)
1. **Scenario:** [Abstract description of the attack]
2. **Payload:**
   ```bash
   # Example of curl or script
   curl -X POST http://target/api/endpoint -d "payload=...'"
   ```
3. **Expected Result:** [What the attacker achieves: shell, data, bypass]

#### 🎯 Risk Analysis
- **Technical Impact:** What the attacker can do on the server/database.
- **Business Impact:** Theft of PII, financial fraud, reputational damage.

#### 🛡️ Remediation (Patch)
**Conceptual Instruction:** What the developer should change (e.g., "Use parameterized queries").

**Contextual Patch:**
```diff
- old_vulnerable_code()
+ new_secure_code_with_sanitization()
```

#### 📌 References
- [[Internal Vault Note Link]]
- [OWASP Top 10 Link (Optional)]

---

## 🎨 Design Principles for Findings
1. **Be Specific:** Do not use generic descriptions. Refer to variables and functions from the project.
2. **Actionable:** The developer must read the "Remediation" and know exactly what to do.
3. **No Speculation:** If you haven't confirmed the sink, don't report it as a vulnerability. Report as "Instruction for Manual Validation" in the **Info** category.
