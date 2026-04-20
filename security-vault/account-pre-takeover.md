# Account Pre-Takeover & Merge Vulnerabilities — Tactical Pillar

> **Context:** An attacker creates an account with a victim's email address *before* the victim registers. When the victim later registers or logs in via OAuth/SSO, the application merges the sessions or hands control to the pre-registered account — which the attacker controls.

**Tags:** #high #authentication #account-takeover #oauth #pre-takeover
**OWASP:** A07:2021 Identification & Authentication Failures
**CVSS Base:** 8.8 (High) — often unauthenticated full account takeover

---

## Attack Class 1: Email Pre-Seeding

**Precondition:** Application allows registration with unverified email + supports OAuth login.

**Kill chain:**
```
1. Attacker registers: victim@example.com / attacker_password (without verifying email)
2. Victim's account doesn't exist yet — registration succeeds.
3. Victim later signs in via "Login with Google" (Google confirms ownership of victim@example.com).
4. Application finds email match → merges OAuth identity with pre-seeded account.
5. Attacker logs in with attacker_password → owns victim's fully-verified account.
```

**`grep_search`:** Logic that merges OAuth identity with an existing email on first login: `findByEmail(`, `upsert(`, `firstOrCreate(`. Verify if email verification is required *before* the account can be used as an OAuth merge target.

---

## Attack Class 2: OAuth Login → Account Merge Without Verification

**Precondition:** Application links OAuth accounts to existing accounts by matching email without re-authentication.

```python
# VULNERABLE
user = User.objects.filter(email=oauth_email).first()
if user:
    user.oauth_id = oauth_provider_id
    user.save()  # Attacker's pre-seeded account is now linked to victim's OAuth
    login(request, user)
```

**Fix:** Require current password authentication before linking a new OAuth provider to an existing account.

---

## Attack Class 3: Password Reset Token Valid After Registration

**Precondition:** Attacker triggers a password reset for the victim's email before the victim registers.

```
1. Attacker calls: POST /forgot-password { email: "victim@example.com" }
   → Server generates token even though no account exists (bugs in some frameworks).
2. Victim registers and creates an account.
3. Attacker uses the old token to reset the new account's password.
```

**`grep_search`:** `/forgot-password` handler — does it check if email is *verified* before generating token? Does the token remain valid after the account state changes (registration)?

---

## Attack Class 4: Insecure Direct Account Link (IDOR in OAuth)

**Precondition:** Application accepts a user-supplied account ID to link with while authenticated to OAuth.

```
POST /link-oauth { account_id: 99999 }
→ Links attacker's OAuth session to any arbitrary account_id
```

**`grep_search`:** OAuth callback handlers that accept `state` or `account_id` parameters without validating ownership.

---

## Strategic Checklist for Auditor
1. [ ] Test: register with target email (without verifying) → then use OAuth → check if sessions merge.
2. [ ] Verify that OAuth-to-existing-account linking requires password re-authentication.
3. [ ] Check if `/forgot-password` generates tokens for non-existent (pre-registration) emails.
4. [ ] Audit OAuth state parameter for IDOR vectors (account_id injection).
5. [ ] Verify email verification is enforced as a hard prerequisite for OAuth merging.

---

## Chained Exploitation Paths

```
Email Pre-seeding + OAuth Merge → Full Account Takeover (zero interaction from victim)
Reset Token Persistence + Registration → Post-Registration Account Reset
IDOR in OAuth Link → Arbitrary Account Hijack via OAuth
```

---

*Tags: #pre-takeover #oauth #account-merge #authentication #idor #shiva-vault*
