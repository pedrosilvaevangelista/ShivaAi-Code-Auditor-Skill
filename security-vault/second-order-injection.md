# Second-Order Injection — Tactical Pillar

> **Context:** Data is sanitized upon entry and persisted (database, logs, config). The vulnerability detonates when the application re-reads this data later and uses it in a dangerous sink without fresh sanitization.

---

## 1. SQL Injection (Second-Order)
- **Scenario:** User sets their username to `admin'--`. The application sanitizes the `INSERT` query correctly.
- **Detonation:** Later, an admin views the user list. The application runs: `SELECT * FROM audits WHERE actor = 'admin'--'`. The query is truncated, potentially bypassing checks or changing logic.
- **`grep_search`:** Trace where data read from the database is used in new queries.

---

## 2. SSTI (Second-Order)
- **Scenario:** User saves a profile biography as `{{7*7}}`.
- **Detonation:** The system later renders this biography using a template engine (Jinja2, Twig, EJS) without escaping. The output shows `49`.
- **`grep_search`:** `render(db_result)`, `template.render(data)`.

---

## 3. Command Injection (Second-Order)
- **Scenario:** A legacy internal tool allows "System Description" to be saved.
- **Detonation:** A nightly cronjob reads these descriptions and runs `echo "Desc: $desc" > /var/log/desc.log`. If `$desc` is `; rm -rf /`, it executes.

---

## 4. XSS (Second-Order)
Most "Stored XSS" are technically second-order injections where the sink is the browser's DOM.
- **`grep_search`:** Any database read followed by `innerHTML`, `res.write`, or template rendering.

---

## Strategic Checklist for Auditor
1. [ ] Identify data persistence points (Write to DB/File).
2. [ ] Locate where this persisted data is retrieved.
3. [ ] Trace the retrieved data to dangerous sinks (Query, Exec, Render).
4. [ ] Pay special attention to "Admin Panels" or "Background Jobs" that process user-controlled data hours/days later.

---

*Tags: #second-order #sqli #ssti #persistence #shiva-vault*
