# API Semantic Desync (JSON vs URL-Encoded) — Tactical Pillar

> **Context:** Also known as Parameter Pollution across content types. It occurs when a WAF, an API Gateway, or a Proxy parses the incoming request differently than the Backend Application due to ambiguous declarations or flexible parsing mechanisms.

---

## 1. WAF vs Backend Desync (Content-Type Smuggling)
- **Scenario:** The client sends a request with `Content-Type: application/json` but the body contains URL-encoded data.
- **Tactic:** The WAF might only inspect JSON because of the header and find nothing malicious. The backend application (e.g., Express.js using both `express.json()` and `express.urlencoded()`) might fail to parse the JSON, fallback to URL-encoded parsing, and successfully process the malicious payload.
- **`grep_search`:** `app.use(express.json())` combined with `app.use(express.urlencoded({ extended: true }))`. Check the order and fallback logic.

## 2. Parameter Source Merging
- **Scenario:** The backend logic merges parameters from the URL Query string, the Body, and Path parameters into a single object (`merged_params`).
- **Tactic:** An attacker passes `{"isAdmin": false}` in the JSON body (which passes validation checks) but appends `?isAdmin=true` in the URL query string.
- If the merging logic is `merged = { ...body, ...query }`, the query parameter overwrites the body parameter.
- **`grep_search`:** `Object.assign(`, `req.query`, `req.body`, `merged =`.

## 3. Duplicate Key Processing (JSON Specific)
- **Scenario:** A JSON payload contains two identical keys: `{"id": 1, "id": 2}`.
- **Tactic:** The WAF might parse the first key (`id=1`) and validate it. The backend JSON parser might parse the second key (`id=2`) and process it.
- **Audit:** Investigate which JSON parser the stack uses and how it handles duplicate keys (first-wins vs last-wins).

## Strategic Checklist
1. [ ] Check how the backend framework handles redundant parameters (list vs overwrite).
2. [ ] Identify routes where data is pulled from multiple sources (Headers, Body, Query) and merged.
3. [ ] Verify if the application enforces strict `Content-Type` matching.

---
*Tags: #api-security #semantic-desync #parameter-pollution #waf-bypass #shiva-vault*
