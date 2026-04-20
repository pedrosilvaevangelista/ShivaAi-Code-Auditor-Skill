# Subdomain Takeover — Tactical Pillar

> **Context:** DNS records pointing to decommissioned cloud resources (GitHub Pages, Heroku, S3, Netlify, Azure, etc.) remain live long after the resource is deleted. An attacker claims the dangling resource and gains control of the subdomain — with its inherited cookies, CORS trust, and CSP scope.

**Tags:** #high #dns #subdomain-takeover #cloud #ato
**OWASP:** A05:2021 Security Misconfiguration
**CVSS Base:** 8.1 (High) — escalates to Critical with session cookie scope

---

## The Vulnerability Lifecycle

```
1. Company creates: staging.target.com → CNAME → target.github.io (GitHub Pages)
2. GitHub Pages project is deleted (resource released).
3. DNS CNAME record is NOT removed (forgotten).

Result: staging.target.com now points to an unclaimed GitHub Pages slot.
Attacker: Creates a new GitHub Pages project at target.github.io.
Outcome: Attacker controls staging.target.com.
```

---

## High-Value Takeover Targets by Provider

| Provider | Dangling Indicator | Takeover Method |
|---|---|---|
| GitHub Pages | `There isn't a GitHub Pages site here` | Create repo targeting the subdomain |
| Heroku | `No such app` | Deploy a new app with the matching name |
| AWS S3 | `NoSuchBucket` | Create a bucket with the exact subdomain name |
| AWS Elastic Beanstalk | `NXDOMAIN on *.elasticbeanstalk.com` | Register the subdomain in same region |
| Netlify | `Not Found - Request ID: ...` | Claim the netlify subdomain |
| Azure (App Service) | `404 Web Site not found` | Register the Azure app with matching name |
| Zendesk | `Help Center Closed` | Register the Zendesk account |
| Shopify | `Sorry, this shop is currently unavailable` | Register a Shopify store |
| Fastly | `Fastly error: unknown domain` | Add the domain to any Fastly service |
| SendGrid | Confirm domain in SendGrid → `CNAME` remains but unverified | Re-verify in a new account |

---

## Impact Taxonomy

### `staging.target.com` class (low reputation subdomain)
- Phishing campaigns under a trusted parent domain.
- Cross-subdomain cookie theft (if `Domain=.target.com`).

### `api.target.com` or `auth.target.com` class (critical subdomains)
- If cookies are scoped to `.target.com`: **Full session hijacking** of authenticated users.
- If in CSP `script-src` whitelist: **CSP bypass → XSS on main domain**.
- If in CORS `Allow-Origin` whitelist: **Cross-origin API reads on behalf of victims**.

**This makes subdomain takeover a force multiplier — the entry point unlocks cookie theft, XSS, and CORS bypass simultaneously.**

---

## Detection Protocol (Static Analysis)

**`grep_search`:** DNS configuration files are rarely in repos. However:
- Search for hardcoded CDN/cloud URLs: `github.io`, `herokuapp.com`, `s3.amazonaws.com`, `netlify.app`, `azurewebsites.net`.
- Check `CORS` origin whitelists and `CSP` headers for subdomains.
- Read any `.github/workflows/` deploy steps for dangling deployment targets.

**External recon (DAST mode):**
```bash
# In .tmp/ — enumerate DNS and check for dangling CNAMEs
dig staging.target.com CNAME
nslookup api.target.com
curl -I https://staging.target.com  # Check for provider-specific error messages
```

---

## Chained Exploitation Paths

```
Subdomain Takeover (staging) + Cookie Scope (.target.com) → Session Hijacking of Production Users
Subdomain Takeover (cdn) + CSP whitelist → XSS on main app → Admin Account Takeover
Subdomain Takeover (api) + CORS whitelist → Read authenticated API responses → Data Exfiltration
Subdomain Takeover + SendGrid → Phishing Emails from Trusted Domain → Credential Harvesting
```

---

## Strategic Checklist for Auditor
1. [ ] Identify all subdomains referenced in CORS, CSP, cookie domains.
2. [ ] Check build/deploy configs for cloud provider names.
3. [ ] In DAST mode: resolve each subdomain and check for dangling-resource error messages.
4. [ ] Assess cookie `Domain` attribute scope — `.target.com` vs `target.com`.
5. [ ] Cross-check subdomains in `script-src` CSP — they are implicit XSS bypass vectors.

---

*Tags: #subdomain-takeover #dns #cloud #cors #csp #cookie-scope #shiva-vault*
