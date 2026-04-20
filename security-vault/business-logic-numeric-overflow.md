# Business Logic: Numeric Overflow & Negative Value Attacks — Tactical Pillar

> **Context:** Financial and inventory systems perform arithmetic on user-supplied values. When boundaries are not enforced, attackers supply negative values, zero, or overflow values to break the intended logic — transferring funds backwards, generating unlimited credits, or bypassing payment gates.

**Tags:** #high #business-logic #integer-overflow #financial #negative-value
**OWASP:** A04:2021 Insecure Design
**CVSS Base:** 7.5–9.1 (High/Critical when financial impact)

---

## Attack Class 1: Negative Quantity / Price

**Scenario:** E-commerce cart allows user to specify item quantity.

```
POST /cart/add
{ "product_id": 123, "quantity": -10 }
```

**Detonation:** Application calculates: `total = price * quantity = $50 * -10 = -$500`. The negative total is subtracted from an existing balance or creates a refund.

**`grep_search`:** Any route that accepts `quantity`, `amount`, `price`, or `discount` and passes it directly to arithmetic without `> 0` validation.

---

## Attack Class 2: Discount Stacking / Coupon Abuse

**Scenario:** The discount system applies codes sequentially without a floor check.

```python
# Each coupon applies to the CURRENT price after previous coupons
price = 100
price -= apply_discount(coupon1)  # → 80
price -= apply_discount(coupon2)  # → 60
price -= apply_discount(coupon3)  # → 40  
# ... apply 10 coupons → price = -$60 (negative — attacker gets credited)
```

**`grep_search`:** Discount/coupon application logic — does it enforce `price = max(price - discount, 0)`?

---

## Attack Class 3: Integer Overflow in Credit Systems

**Scenario:** Reward points or in-app credits stored as a fixed-size integer.

```
Current credits: 2,147,483,647 (INT32_MAX)
Add 1 credit → overflows to: -2,147,483,648
Application: user now owes 2 billion credits (signed underflow)
```

**Reverse scenario (attacker-beneficial):**
```
Current balance: 0
Transfer -$2,147,483,647 → application treats it as receiving +$2,147,483,647
```

**`grep_search`:** `INT`, `Integer`, credit/balance column types in database schema. Languages using 32-bit integers for financial values: `int balance` in Java, `int credits` in PHP.

---

## Attack Class 4: Free Item via Rounding Exploit

**Scenario:** A $0.005 item rounds to $0.00 in some implementations. Attacker adds 1,000 units at $0.00 each.

**`grep_search`:** Monetary calculation using floating-point (`float`, `double`) instead of decimal types. `FLOAT` in database schemas for price columns is an immediate finding.

---

## Attack Class 5: Race Condition on Balance Check (TOCTOU Financial)

**Scenario:** Check balance → approve → deduct. All three steps are non-atomic.

```
Thread A: checkBalance($100)  → passes
Thread B: checkBalance($100)  → passes (same $100 seen!)
Thread A: deduct($100)        → balance = $0
Thread B: deduct($100)        → balance = -$100 (overdraft)
```

**`grep_search`:** Financial deduction operations without `SELECT FOR UPDATE` or database-level transaction locks: `BEGIN TRANSACTION`, `LOCK`, `mutex`. **Absence** in balance-check → deduct flows is the vulnerability.

---

## Attack Class 6: Zero-Value Payment Bypass

**Scenario:** Application skips payment processing when total is $0.

```python
total = calculate_cart()
if total == 0:
    mark_order_paid()  # Skips payment gateway entirely
    return "Order confirmed"
```

**Tactic:** Attacker applies so many discounts that total reaches $0 — getting products for free.

**`grep_search`:** `if total == 0`, `if amount <= 0: skip_payment`. Verify these code paths still enforce a valid entitlement (coupons are legitimate, not stacked).

---

## Strategic Checklist for Auditor
1. [ ] Test negative values for all quantity, amount, and price parameters.
2. [ ] Apply multiple discount codes and verify a minimum price floor is enforced.
3. [ ] Check database schema: price/balance columns should be `DECIMAL`/`NUMERIC`, never `FLOAT`.
4. [ ] Look for integer types on credit/reward systems and test overflow boundaries.
5. [ ] Check for `if total == 0: skip_payment` patterns.
6. [ ] Verify balance deduction operations use atomic transactions or `SELECT FOR UPDATE`.

---

## Chained Exploitation Paths

```
Negative Quantity + Cart Total → Negative balance → Credited funds on account
Discount Stacking + Zero-Value Check → Free order fulfillment
TOCTOU Balance + Concurrent Transfers → Overdraft / Double-spend
Rounding Exploit + Bulk Add → Items acquired at $0 cost
```

---

*Tags: #business-logic #integer-overflow #negative-value #financial #discount-abuse #toctou #shiva-vault*
