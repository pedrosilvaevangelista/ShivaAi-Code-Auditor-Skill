# Clickjacking & UI Redressing — Elite Protocol

> **Context:** The victim's browser loads the target application inside a transparent `<iframe>` overlaid on an attacker-controlled page. The attacker's visible UI is designed to trick the user into clicking on specific coordinates that map to sensitive actions inside the invisible iframe.

**Tags:** #medium #clickjacking #csrf #ui-redressing #iframe
**OWASP:** A05:2021 Security Misconfiguration
**CVSS Base:** 4.7–7.1 (High if target action is destructive or financial)

---

## Why Frame Headers Are the Only Real Fix

JavaScript cannot detect it, CSRF tokens don't prevent it (it's a legitimate authenticated request), and user awareness training fails against a polished decoy UI. **The only structural mitigation is the `X-Frame-Options` or `frame-ancestors` CSP directive.**

---

## Attack Classes

### 1. Classic Single-Click Clickjacking

**Scenario:** Target is a "Delete Account" button at coordinates `(420, 310)`.

**Attack HTML:**
```html
<style>
  iframe {
    position: absolute; top: 0; left: 0;
    width: 100%; height: 100%;
    opacity: 0.0001; /* Nearly invisible */
    z-index: 2;
  }
  .decoy-btn {
    position: absolute; top: 310px; left: 420px;
    z-index: 1;
  }
</style>
<div class="decoy-btn">🎁 Claim Your Prize!</div>
<iframe src="https://target.com/account/settings"></iframe>
```

**Result:** User clicks the decoy button → actually clicks "Delete Account" on target.

---

### 2. Likejacking (Social Engineering Amplification)

**Scenario:** A Facebook "Like" or Twitter "Follow" button embedded in a page at attacker-controlled coordinates.
- **The overlay button** says "Play Video" or "Spin the Wheel".
- **Beneath it:** The social button is positioned exactly.
- **Result:** Millions of low-effort social media actions without user consent.

---

### 3. Drag-and-Drop Token Exfiltration

**The attack:** Using browser drag-and-drop APIs to exfiltrate CSRF tokens or session cookies from a framed page into an attacker-controlled text input.

**Steps:**
1. Victim visits attacker's page.
2. Page frames the target app which renders a CSRF token in a form.
3. A drag event is initiated from the iframe textarea (target app's token) to a visible text input on the attacker's page.
4. Token value is captured.

**`grep_search`:** Token rendered in visible DOM elements (not hidden inputs) on critical pages.

---

### 4. Multi-Step Clickjacking (Multi-Click Chain)

**Scenario:** Bypassing "Are you sure?" multi-step confirmation flows.
- Step 1 decoy: "Answer the quiz!"
- Step 2 decoy: "Confirm your answer!"
- Each click advances the invisible target form's confirmation state.

**Result:** Actions requiring explicit multi-step confirmation are completed without user awareness.

---

### 5. Cursorjacking

CSS cursor repositioning tricks the user into thinking they're clicking elsewhere. The `cursor: none` property hides the real cursor and a CSS element simulates a fake cursor at an offset position.

```css
* { cursor: none !important; }
.fake-cursor { cursor: pointer; position: absolute; /* offset position */ }
```

**Result:** User aims at one location but the real click registers at the fake cursor position over the iframe.

---

## Detection Protocol (Static Analysis)

**Tier 1 — Response Header Check:**
```
Missing: X-Frame-Options: DENY
Missing: X-Frame-Options: SAMEORIGIN
Missing: Content-Security-Policy: frame-ancestors 'none'
Missing: Content-Security-Policy: frame-ancestors 'self'
```

**`grep_search`:**
- `X-Frame-Options` in server configs, middleware, or route handlers.
- `frameguard(` (Helmet.js) — absence means Express apps leak frame-ability.
- `res.setHeader('X-Frame-Options'` — verify value is `DENY`, not `ALLOW-FROM` (deprecated).
- In Nginx/Apache configs: `add_header X-Frame-Options`.

**Tier 2 — CSP frame-ancestors (Preferred Modern Standard):**
```http
Content-Security-Policy: frame-ancestors 'none'  # Strictest
Content-Security-Policy: frame-ancestors 'self'  # Allows same-origin framing only
```

Note: `frame-ancestors` overrides `X-Frame-Options` in modern browsers and cannot be bypassed via meta tags.

---

## Detection Script — DAST Probe

```python
# .tmp/check_clickjacking.py
import requests

TARGET = "https://target.com"
resp = requests.get(TARGET, allow_redirects=True)

xfo = resp.headers.get("X-Frame-Options", "MISSING")
csp = resp.headers.get("Content-Security-Policy", "")
frame_ancestors = "frame-ancestors" in csp

if frame_ancestors:
    print(f"[OK] CSP frame-ancestors directive present.")
elif xfo.upper() in ("DENY", "SAMEORIGIN"):
    print(f"[OK] X-Frame-Options: {xfo}")
else:
    print(f"[HIGH] Clickjacking protection MISSING. X-Frame-Options: {xfo}, frame-ancestors in CSP: {frame_ancestors}")
```

---

## Priority Targets (Where Clickjacking is Critical)

High-risk actions that become Critical when clickjackable:
- Fund transfers / payment initiation.
- "Grant admin access" or "Add SSH key" flows.
- OAuth authorization grant screens.
- Password change without current password confirmation.
- Account deletion.

**If the target is a banking app or OAuth provider — escalate immediately to Critical.**

---

## Chained Exploitation Paths

```
Clickjacking + OAuth Grant Screen → Unauthorized App Authorization → Full Account Access
Clickjacking + Fund Transfer → Financial Theft (no interaction needed beyond 1 click)
Clickjacking + Admin Action → Privilege Escalation (Add Attacker as Admin)
Clickjacking + Drag-Drop → CSRF Token Exfiltration → Arbitrary State-Changing Requests
Cursorjacking + Sensitive Form → Credential Submission to Wrong Target
```

---

## Strategic Checklist for Auditor
1. [ ] Check `X-Frame-Options` and `Content-Security-Policy: frame-ancestors` on ALL pages, not just the home page.
2. [ ] Focus on pages with destructive/financial/privilege-escalation actions.
3. [ ] Verify OAuth authorization screens explicitly — these are the highest-impact targets.
4. [ ] Run the DAST detection script for each application endpoint.
5. [ ] Note: `ALLOW-FROM` in X-Frame-Options is deprecated and unsupported by modern browsers — treat as equivalent to missing.

---

*Tags: #clickjacking #ui-redressing #csrf #iframe #frameguard #shiva-vault*
