# Forensic Anti-Recon (Log Injection/Tampering) — Tactical Pillar

> **Context:** An attacker leverages application vulnerabilities not just to steal data, but to manipulate the forensic trail. This involves injecting false logs, erasing traces, or triggering log overflow to cover up malicious actions.

---

## 1. CRLF Log Injection (Log Forging)
- **Scenario:** User input is written directly into application logs without sanitization of control characters.
- **Tactic:** The attacker submits a malicious username: `admin\r\n[INFO] 2026-04-20 User admin successfully logged in`.
- **Detonation:** The log file reads as two separate, legitimate-looking entries. The attacker completely subverts the audit trail.
- **`grep_search`:** `logger.info(`, `console.log(`, `logging.getLogger`. 

## 2. Terminal Escape Sequences (Log Poisoning)
- **Scenario:** The application logs input that administrator terminals will `cat` or `tail`.
- **Tactic:** The attacker injects ANSI escape sequences (e.g., `\e[2J` to clear the screen, or `\b` backspaces).
- **Detonation:** When the Sysadmin reviews the logs in a terminal, the malicious entry erases itself or manipulates the terminal output to hide the preceding attack logs.

## 3. Log Overconsumption (DoS via Logs)
- **Scenario:** The application logs large payloads indiscriminately on errors.
- **Tactic:** Attacker sends massive payloads in a loop to trigger errors.
- **Detonation:** The disk fills up (`/var/log/`), causing a Denial of Service, or the excessive logging flushes out the actual attack logs through log rotation.

## Strategic Checklist
1. [ ] Trace all paths where unfiltered user input reaches the logging engine.
2. [ ] Verify if the logging library escapes `\r`, `\n`, `\t` and ANSI codes.
3. [ ] Check log configurations for size limits and rotation metrics.

---
*Tags: #log-injection #anti-forensics #log-forging #shiva-vault*
