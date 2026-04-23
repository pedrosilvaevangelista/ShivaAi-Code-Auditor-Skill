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

## 4. HTTP/2 to HTTP/1.1 Downgrade Smuggling
- **Scenario:** The reverse proxy accepts HTTP/2 (which uses binary frames for headers) and translates it to HTTP/1.1 text to send to the backend.
- **Tactic:** Attacker injects CRLF (`\r\n`) within HTTP/2 pseudo-headers (e.g., `:path`). The proxy passes it as plain text in HTTP/1.1, splitting the request and smuggling a secondary request to the backend.
- **`grep_search`:** `http2`, `proxy_pass`, `allowHTTP1: true`.

## 5. Type Confusion (Weakly Typed Languages)
- **Scenario:** The API expects a string ID but receives an array or an object via JSON or URL Query (`?id[]=1`).
- **Tactic:** If PHP receives an array where it expects a string, `strcmp(array, "admin")` returns `0` (true) in older versions. In Node.js, passing an array to a regex or SQL query can cause a DoS or bypass the filter.
- **`grep_search`:** `strcmp(`, `req.query.id`, `typeof`.

## Strategic Checklist
1. [ ] Check how the backend framework handles redundant parameters (list vs overwrite).
2. [ ] Identify routes where data is pulled from multiple sources (Headers, Body, Query) and merged.
3. [ ] Verify if the application enforces strict `Content-Type` matching.
4. [ ] Test parameter type variations (String -> Array -> Object).

---
*Tags: #api-security #semantic-desync #parameter-pollution #waf-bypass #http2 #type-confusion #shiva-vault*
