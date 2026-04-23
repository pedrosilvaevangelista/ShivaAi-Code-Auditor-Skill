# Webhook & Asynchronous Callback Security — Tactical Pillar

> **Context:** Applications heavily rely on third-party integrations (Stripe, GitHub, Twilio) that send asynchronous HTTP POST requests (webhooks) to notify the application of events. This surface is highly vulnerable to spoofing, replay attacks, and race conditions.

---

## 1. Webhook Spoofing (Missing Signature Validation)
- **Scenario:** The application receives a payment success notification (`POST /api/webhooks/stripe`) and updates the user's balance without verifying the sender.
- **Tactic:** Attacker discovers the endpoint and sends a forged payload: `{"type": "payment_intent.succeeded", "amount": 10000, "customer": "cus_123"}`. The application processes it, granting free credits.
- **`grep_search`:** `webhook`, `req.body`, `stripe-signature`, `crypto.createHmac`.
- **Fix:** Always validate the `X-Hub-Signature`, `Stripe-Signature`, or equivalent HMAC header using the shared secret.

## 2. Webhook Replay Attacks
- **Scenario:** The application validates the HMAC signature correctly but does not check if the event was already processed.
- **Tactic:** Attacker intercepts a legitimate "payment successful" webhook (or accesses it from a dashboard leak) and resends the exact same HTTP request 50 times. The signature is valid, so the app credits the account 50 times.
- **`grep_search`:** Check if the webhook processing logic maintains an idempotency key store (e.g., storing the `event_id` in Redis or DB) and drops duplicates.

## 3. Blind SSRF via Webhook Registration
- **Scenario:** The application allows users to register their own webhooks (e.g., "Send a POST to this URL when my build finishes").
- **Tactic:** Attacker registers `http://169.254.169.254/latest/meta-data/` or `http://localhost:6379/`. When the event triggers, the application's backend server makes a blind POST request to its own internal services or cloud metadata.
- **`grep_search`:** `webhook_url`, `axios.post(user_url`, `fetch(webhook.url)`.

## 4. Race Conditions in Asynchronous Callbacks
- **Scenario:** A user performs an action that triggers a webhook to a 3rd party, which then calls back. 
- **Tactic:** Attacker initiates the action twice rapidly. If the webhooks arrive back at the same time and the backend lacks database locks (`SELECT FOR UPDATE`), both callbacks might process simultaneously, doubling the result (e.g., duplicate refunds).
- **`grep_search`:** `beginTransaction`, `lock`, `SELECT FOR UPDATE` in webhook handlers.

## Strategic Checklist
1. [ ] Identify all webhook listener endpoints (`/webhook`, `/callback`, `/events`).
2. [ ] Audit the HMAC signature verification logic for timing attacks (use `crypto.timingSafeEqual`).
3. [ ] Verify idempotency: are `event.id`s tracked to prevent replays?
4. [ ] If the app sends webhooks to user-supplied URLs, audit for SSRF and SSRF via DNS Rebinding.

---
*Tags: #webhooks #ssrf #replay-attack #race-condition #payment-bypass #shiva-vault*
