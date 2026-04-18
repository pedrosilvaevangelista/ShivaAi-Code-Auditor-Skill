# Business Logic Flaws

**Tags:** #alto #logica-de-negocio #idor #race-condition #fluxo
**OWASP:** A04:2021 — Insecure Design
**CVSS Base:** Variável — até 9.8 (Crítico — fraude financeira, privilege escalation)

---

## 📖 O que é

Business Logic Flaws são vulnerabilidades no **design intencional** da aplicação — não em seu código. Nenhum scanner automatizado detecta por definição; requer simular o papel de usuário malicioso tentando subverter o fluxo intencional.

> *"O scanner encontra vulnerabilidades de implementação. O auditor encontra vulnerabilidades de design."*

---

## 🧠 Perguntas-Chave do Auditor

1. **"Posso pular uma etapa do fluxo?"** — Checkout sem passar pelo carrinho? Admin sem verificar 2FA?
2. **"Posso aplicar um desconto negativo?"** — Campos de quantidade ou preço aceitam valor negativo?
3. **"Posso acessar o recurso de outro usuário trocando um ID?"** → [[IDOR & BOLA — Broken Object Level Authorization]]
4. **"Posso fazer duas operações simultâneas?"** → [[Race Condition & TOCTOU]]
5. **"Posso ir direto para a URL final sem completar o processo?"** — Bypass de multi-step flows
6. **"O que acontece se eu manipular o estado assumido?"** — Cookie de etapa de pagamento

---

## 💣 Padrões de Vulnerabilidade

### 1. Bypass de Fluxo Multi-Step

```
Fluxo intencional:
  /checkout/step1 (informações)
  → /checkout/step2 (endereço)  
  → /checkout/step3 (pagamento)
  → /checkout/confirm

Ataque: ir direto para /checkout/confirm sem completar os steps
→ Pedido sem pagamento? Endereço de entrega vazio?
```

**Protocolo:** identificar endpoints de "confirmação" que não verificam estado de sessão/banco dos steps anteriores.

---

### 2. Manipulação de Valores Numéricos

```javascript
// ❌ VULNERÁVEL — não valida quantidade negativa
app.post('/cart/add', (req, res) => {
    const { product_id, quantity } = req.body;
    // quantity pode ser -100!
    cart.add(product_id, quantity);  // desconto infinito
});
```

```python
# ❌ VULNERÁVEL — campo de desconto controlado pelo usuário
@app.post('/apply-coupon')
def apply_coupon():
    discount = float(request.json['discount'])
    # Negativo = aumento de preço ou número gigante = total negativo
    order.total -= discount
```

---

### 3. Privilege Escalation por Parâmetro Escondido

```http
POST /api/register HTTP/1.1
Content-Type: application/json

{
    "email": "attacker@evil.com",
    "password": "hunter2",
    "role": "admin",        ← tentar adicionar este campo
    "is_admin": true,
    "verified": true
}
```

→ Ver também: [[Mass Assignment]]

---

### 4. Coupon/Voucher Abuse

```
Cupom de 10% de desconto, reutilizável:
→ Usar o mesmo cupom em 1000 pedidos simultâneos (Race Condition)
→ Usar cupom em si mesmo (cupom no desconto do cupom)
→ Cupom para "novo usuário" mas conta cadastrada há anos — validação só por email?
→ Coupon code previsível (SEQ-001, SEQ-002... tentar SEQ-1000)
```

---

### 5. Lógica de Autorização Apenas no Frontend

```javascript
// Frontend React — botão "Deletar" escondido para não-admins
{userRole === 'admin' && <button onClick={deleteUser}>Deletar</button>}

// Backend — sem verificação correspondente
app.delete('/api/users/:id', async (req, res) => {
    await User.delete(req.params.id);  // ← qualquer usuário autenticado pode fazer via curl!
    res.json({ success: true });
});
```

**Protocolo:** para cada ação protegida no frontend, verificar se o backend também verifica.

---

### 6. Reembolso/Estorno Abusável

```
Fluxo: Comprar → produto chega → solicitar reembolso

Ataque: 
1. Solicitar reembolso antes de o produto ser entregue
2. Solicitar reembolso e manter o produto (se não há verificação de devolução)
3. Reembolso parcial = crédito negativo que vira saldo positivo
```

---

### 7. Enumeração de Regras de Negócio

```
"Usuário premium tem acesso a relatórios avançados"
→ Verificar: o backend verifica a flag 'premium' em CADA requisição?
→ Ou a flag é armazenada em cookie não-assinado?

Ataque: modificar o cookie
document.cookie = "plan=premium"; // ou via DevTools
→ Se o backend confiar no cookie → acesso premium gratuito
```

---

## 🔍 `grep_search` Táticas

```
# Verificações de estado no fluxo
step
stage
phase
completed
verified
is_admin
role
premium
plan

# Valores numéricos sem validação de range
quantity
discount
amount
price
balance
credit
```

---

## 🧪 Checklist de Análise de Fluxo

```
Para cada funcionalidade de negócio relevante:

[ ] O backend valida TODOS os steps do fluxo, ou confia no frontend?
[ ] Parâmetros numéricos aceitam valores negativos? Muito grandes?
[ ] Operações sensíveis são atômicas (transações)? → Race Condition
[ ] O estado de "autorizado" é verificado server-side a cada requisição?
[ ] Cupons/vouchers são invalidados após uso único?
[ ] Operações irreversíveis têm confirmação verificada server-side?
[ ] Campos de role/admin podem ser enviados e aceitos pelo backend?
[ ] Flags de autorização vivem em cookies não-assinados?
```

---

## 🔗 Chain Exploits

```
Fluxo multi-step bypass + pagamento = Compras sem pagar
Quantidade negativa + checkout = Crédito na conta
Lógica apenas no frontend + ação admin = Privilege escalation trivial
Coupon abuse + Race Condition = Desconto infinito
Parâmetro role= + Mass Assignment = Admin sem cadastro especial
```

---

## 📌 Referências
- [[Mass Assignment]]
- [[Race Condition & TOCTOU]]
- [[IDOR & BOLA — Broken Object Level Authorization]]
- [OWASP Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
