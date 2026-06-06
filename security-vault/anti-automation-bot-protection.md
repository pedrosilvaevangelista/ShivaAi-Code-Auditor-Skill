# Anti-Automation & Rate Limiting (Bot Protection)

**Tags:** #high #rate-limit #bot #automation #scalping #brute-force
**OWASP:** A06:2025 Insecure Design
**CVSS Base:** 5.3 (Medium) — 7.5 (High → if leading to account takeover or massive financial loss)

---

## 📖 What is it

Improper Control of Interaction Frequency (CWE-799) is a design flaw where the application does not limit how often a user or IP can perform a specific action.

Without anti-automation controls (rate limiting, captchas, proof of work, behavioral analysis), attackers can deploy bots to brute-force passwords, scrape data, spam forms, or scalp inventory (e.g., buying all tickets/GPUs in seconds).

---

## 🎯 OWASP 2025 Scenarios

### Scenario #3: Scalping Bots
A retail chain’s e-commerce website does not have protection against bots run by scalpers buying high-end video cards. 
**Design Flaw:** The system assumes all HTTP requests come from humans typing at a normal speed. 
**Fix:** Careful anti-bot design and domain logic rules, such as identifying if a purchase was made within milliseconds of availability, and rejecting inauthentic transactions.

---

## 🔍 `grep_search` Tactics

```
# Look for missing rate limiters on critical routes
/login
/register
/forgot-password
/checkout
/api/otp

# Look for generic rate limiting libraries (or their absence)
express-rate-limit
flask-limiter
ratelimit
@RateLimiter
```

---

## 💣 Vulnerability Patterns

### 1. No Rate Limiting on Authentication
```javascript
//  VULNERABLE — Infinite login attempts allowed
app.post('/api/login', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (user && await bcrypt.compare(req.body.password, user.password)) {
        // ...
    }
});
```
**Impact:** Credential Stuffing / Brute Force.

### 2. Lack of CAPTCHA on Sensitive Forms
```python
#  VULNERABLE — Password reset without CAPTCHA or limits
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    email = request.form['email']
    send_reset_email(email)
```
**Impact:** Email bombing / SMS toll fraud.

### 3. Predictable Identifiers for Automation
```http
POST /api/purchase
{ "item_id": 1001, "qty": 1 }
```
If an attacker can enumerate `item_id` sequentially, they can automate purchasing logic for the entire catalog without scraping the UI.

---

## 💣 Exploit Techniques & Bypasses

### 1. IP Rotation Bypass
If rate limiting is strictly IP-based:
- Attackers use rotating proxies (AWS API Gateway, Residential Proxy Networks).
- **Mitigation:** Rate limit by user account, device fingerprint, or session ID in addition to IP.

### 2. `X-Forwarded-For` Spoofing
If the backend trusts the `X-Forwarded-For` header to determine the client IP:
```http
POST /login
X-Forwarded-For: 1.2.3.4
```
The attacker simply randomizes this header on every request, bypassing the IP-based rate limiter completely.

### 3. Logic-Based Bypasses
- Appending null bytes or trailing spaces to emails: `admin@site.com` vs `admin@site.com ` (bypasses lockout counters tied to exact string match).
- Changing endpoints: `/api/v1/login` is rate-limited, but `/api/v2/login` or the XML-RPC endpoint is not.

---

## ✅ Secure Design / Fixes

A robust anti-automation design requires multiple layers:

1. **WAF & Edge Rules:** Cloudflare/AWS WAF Bot Control to block known data center IPs and headless browsers.
2. **Application Rate Limiting:**
```javascript
//  CORRECT — Express Rate Limit
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login requests per window
  message: 'Too many login attempts, please try again later'
});
app.use('/api/login', loginLimiter);
```
3. **Behavioral Analysis:** Rejecting forms submitted faster than humanly possible (e.g., < 1 second).
4. **Honeypots:** Hidden fields in forms that bots fill out but humans don't see. If filled, drop the request.

---

## 📌 References
- [OWASP A06:2025 Insecure Design](https://owasp.org/Top10/)
- [[business-logic-flaws]]
