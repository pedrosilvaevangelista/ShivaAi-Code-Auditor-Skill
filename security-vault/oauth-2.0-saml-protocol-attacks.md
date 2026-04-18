# OAuth 2.0 & SAML — Protocol Attacks

**Tags:** #high #critical #oauth #saml #sso #token-theft #account-takeover
**OWASP:** A07:2021 Identification and Authentication Failures
**CVSS Base:** 8.1 (High) — 9.3 (Critical — account takeover without interaction)

---

## 📖 What it is

OAuth 2.0 and SAML are authentication/authorization protocols with specific architectural flaws that go beyond code vulnerabilities — they require protocol flow analysis.

---

## 🔍 `grep_search` Tactics

```
passport.use(new OAuth
oauth2
saml
xmldom
xml-crypto
SimpleSAMLphp
state
redirect_uri
code
access_token
PKCE
code_verifier
code_challenge
authorizationUrl
tokenUrl
```

---

## 💣 OAuth 2.0 — Attacks

### 1. CSRF in OAuth (Missing or Unvalidated State)

**How it works:** the `state` parameter must be randomly generated, associated with the user's session, and verified when the authorization code returns. Without it, an attacker forces the victim to link their account with the attacker's account.

```javascript
//  VULNERABLE  no state
app.get('/oauth/login', (req, res) => {
    const authUrl = `https://provider.com/oauth/authorize?` +
        `client_id=${CLIENT_ID}&` +
        `redirect_uri=${CALLBACK_URL}&` +
        `response_type=code`;
        //  No &state=...
    res.redirect(authUrl);
});
```

**OAuth CSRF Exploit (Account Linking Attack):**
```
1. Attacker initiates the OAuth flow on the target site
2. Obtains the authorization URL without state
3. Tricks the victim into accessing the authorization URL (via phishing/CSRF)
4. Victim authenticates with the provider
5. The victim's authorization code goes to the target site's callback
6. The site associates the victim's OAuth account with the attacker's session
7. Attacker can now log in as the victim
```

---

### 2. Authorization Code Leakage via Referer

```
1. redirect_uri  page that loads external resources (CDN, analytics)
2. The browser sends the ?code=XXX in the Referer header to those external services
3. The authorization code leaks into those services' logs
```

**Static detection:** check if the callback page has links to external resources (`<script src="https://cdn...">`, `<img src="https://analytics...">`).

---

### 3. Open Redirect in redirect_uri

```
# If the server accepts redirect_uri with open redirect:
https://target.com/oauth/callback?redirect=/../../evil.com

# The authorization code is sent to the attacker's domain
```

See: [[open-redirect]]

---

### 4. Missing PKCE (Implicit Flow)

```
# Implicit Flow (legacy) returns the token directly in the URL:
https://app.com/callback#access_token=eyJ...&token_type=bearer

# Token exposed in:
- Server logs (URL with fragment rarely logged, but possible)
- Browser history (fragment is not sent to the server, but stays in history)
- Referer header from subsequent pages
- URL sharing
```

**PKCE Bypass (without S256):**
```
If the server accepts code_challenge_method=plain (instead of S256):
The attacker can intercept the code_verifier from "plain" easily
```

---

## 💣 SAML — Attacks

### 1. XML Signature Wrapping (XSW)

**How it works:** the SAML parser validates the digital signature on one element, but the system *uses* a different (unsigned) element from the same request.

```xml
<!-- Legitimate signed SAML response -->
<Response>
    <Signature>...</Signature>
    <Assertion>
        <Subject>
            <NameID>user@legitimate.com</NameID>
        </Subject>
    </Assertion>
</Response>

<!--  Attacker inserts an unsigned malicious element -->

<Response>
    <Assertion>
        <Subject>
            <NameID>admin@company.com</NameID>   attacker's account
        </Subject>
    </Assertion>
    <Signature>
        <SignedInfo>
            <!-- References the legitimate element below -->
        </SignedInfo>
    </Signature>
    <Assertion id="signed-assertion">
        <Subject>
            <NameID>user@legitimate.com</NameID>   legitimately signed
        </Subject>
    </Assertion>
</Response>

<!-- System validates the signature on the legitimate element, but uses the first
     (unsigned) element = login as admin@company.com without a valid signature -->
```

---

### 2. Comment Injection

```xml
<!-- Parser bypass with XML comment -->
<NameID>user@evil.com<!--</NameID><NameID Id="vulnerable">-->@trusted.com</NameID>
```

Some SAML parsers interpret the NameID differently from signature validation.

---

### 3. Signature Stripping

```xml
<!-- Remove the signature entirely -->
<!-- If the SP (Service Provider) does not require a signature  accepts any assertion -->
<Assertion>
    <Subject>
        <NameID>admin@company.com</NameID>
    </Subject>
    <!-- <Signature>...</Signature>  removed -->
</Assertion>
```

**Detection:** check if `WantsAssertionsSigned` is `true` in the SP metadata.

---

## 🧪 OAuth Flow Verification

```python
# .tmp/check_oauth_state.py
import requests, re

TARGET = "http://target.com"
OAUTH_INIT = "/auth/oauth/login"  # endpoint that initiates OAuth

r = requests.get(f"{TARGET}{OAUTH_INIT}", allow_redirects=False)
location = r.headers.get('Location', '')

print(f"Redirect URL: {location}")

if 'state=' in location:
    state = re.search(r'state=([^&]+)', location)
    print(f" State present: {state.group(1) if state else 'yes'}")
    print("    Also verify if state is validated in the callback!")
else:
    print("🔴 VULN: State MISSING in OAuth flow  CSRF possible!")

if 'response_type=token' in location:
    print("🔴 VULN: Implicit Flow detected  token exposed in URL!")

if 'code_challenge' not in location:
    print("️  INFO: PKCE not implemented  verify if flow is public")
```

---

## 🛡️ OAuth Fix

```javascript
//  CORRECT  Passport.js with state and PKCE
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');
const crypto = require('crypto');

passport.use(new OAuth2Strategy({
    authorizationURL: 'https://provider.com/oauth/authorize',
    tokenURL: 'https://provider.com/oauth/token',
    clientID: process.env.OAUTH_CLIENT_ID,
    clientSecret: process.env.OAUTH_CLIENT_SECRET,
    callbackURL: 'https://myapp.com/oauth/callback',
    state: true,         //  enable automatic state
    pkce: true,          //  enable PKCE (S256)
}, async (accessToken, refreshToken, profile, cb) => {
    // Verify that state matches before processing the profile
    const user = await User.findOrCreate({ providerId: profile.id });
    return cb(null, user);
}));
```

---

## 🔗 Chain Exploits

```
OAuth CSRF (no state)  Account Linking  Victim account takeover
Authorization Code Leakage + replay attack  Login as victim
XSW SAML  Admin account takeover via corporate SSO
SAML Signature Stripping + assert any email  Admin login without credentials
OAuth Implicit Flow + Referer + third-party analytics  Token in analytics logs
Open Redirect + redirect_uri + OAuth code  Full token theft
```

---

## 📌 References
- [[jwt-algorithm-confusion-attacks]]
- [[open-redirect]]
- [[authentication-session-management]]
- [[xml-external-entity-xxe]]
- [PortSwigger OAuth](https://portswigger.net/web-security/oauth)
- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)