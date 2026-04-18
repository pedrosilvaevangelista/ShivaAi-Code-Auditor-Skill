# ReDoS — Regex Denial of Service

**Tags:** #medium #redos #dos #regex #node
**OWASP:** A04:2021 Insecure Design
**CVSS Base:** 6.5 (Medium) — DoS via thread blocking

---

## 📖 What it is

ReDoS (Regular Expression Denial of Service) occurs when a regex pattern with **catastrophic backtracking** processes attacker-controlled input. A 50-character input can lock 100% of a Node.js thread for seconds — an effective DoS. JavaScript is single-threaded, making this especially devastating.

---

## 🔍 `grep_search` Tactics

```
new RegExp(userInput
RegExp(req.
new RegExp(req.
test(
match(
exec(
replace(
```

**Also check:** static regexes with nested quantifiers (do not depend on external input, but any valid input can trigger them):

```
([a-zA-Z]+)*
(a+)+
(a|aa)+
(.*)*
(\d+)+
```

---

## 💣 Vulnerable Regex Patterns (Catastrophic Backtracking)

| Pattern | Risk |
|---|---|
| `(a+)+` | Catastrophic for `"aaaaaaaab"` |
| `([a-zA-Z]+)*` | Catastrophic for `"aaaaaaaa!"` |
| `(a\|aa)+$` | Catastrophic |
| `(.+\s?)*` | Catastrophic |
| `(w+\s?)+` | Catastrophic in email validation |
| `^(([a-z]+B)+\|A)*$` | Catastrophic |

---

## 💣 Vulnerable Code Examples

### Regex Built from User Input

```javascript
//  VULNERABLE  applying user-supplied regex to data
app.post('/search', (req, res) => {
    const pattern = req.body.pattern;
    const data = getAllData();
    
    // Regex built from user input!
    const regex = new RegExp(pattern, 'g');
    const results = data.filter(item => regex.test(item));
    res.json(results);
});

// Exploit: pattern = "(.*)*a" with a long string  locks the process
```

### Static Regex with Backtracking

```javascript
//  VULNERABLE  regex with nested quantifiers
function validateEmail(email) {
    // Pattern vulnerable to ReDoS
    const emailRegex = /^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$/;
    return emailRegex.test(email);
}

// Exploit: "aaaaaaaaaaaaaaaaaaaaaaaaaaa@"  catastrophic
```

---

## 🧪 ReDoS Validation Script

```python
# .tmp/validate_redos.py
import re, time

# Patterns to test
PATTERNS_TO_TEST = [
    r'([a-zA-Z]+)*',
    r'(a+)+',
    r'(a|aa)+',
    r'(\w+\s?)+',
    r'^(([a-z]+B)+|A)*$',
]

# Inputs that cause catastrophic backtracking
def generate_evil_input(base_char='a', length=30):
    return base_char * length + 'X'  # X at the end forces backtracking

print("=== ReDoS Vulnerability Test ===\n")

for pattern in PATTERNS_TO_TEST:
    evil_input = generate_evil_input(length=30)
    
    start = time.time()
    try:
        result = re.search(pattern, evil_input, timeout=3)  # timeout to avoid hanging
        elapsed = time.time() - start
        
        if elapsed > 1.0:
            print(f"[🔴 VULN - {elapsed:.2f}s] ReDoS: /{pattern}/")
            print(f"  Malicious input: {evil_input[:50]}")
        else:
            print(f"[ok - {elapsed:.4f}s] /{pattern}/")
    except re.error:
        print(f"[invalid] /{pattern}/ compilation error")
    except TimeoutError:
        elapsed = time.time() - start
        print(f"[🔴 VULN - TIMEOUT {elapsed:.2f}s] ReDoS: /{pattern}/")
```

---

## 🛡️ Fix

### 1. Never Build Regex from User Input

```javascript
//  CORRECT  literal string search instead of regex
app.post('/search', (req, res) => {
    const searchTerm = req.body.query;
    
    // Literal search, not regex
    const results = data.filter(item => 
        item.toLowerCase().includes(searchTerm.toLowerCase())
    );
    res.json(results);
});
```

### 2. Use Regex Without Backtracking (Possessive Quantifiers / Atomic Groups)

```javascript
// If regex is required with user input:
// Validate the input first before using regex

function safeSearch(userPattern, data) {
    // Check if the pattern contains dangerous constructs
    const dangerousPatterns = [
        /(\|)+\+/,  // quantified OR groups
        /\([^)]+\)\+/,  // groups with +
        /\([^)]+\)\*/,  // groups with *
    ];
    
    for (const danger of dangerousPatterns) {
        if (danger.test(userPattern)) {
            throw new Error("Dangerous regex pattern rejected");
        }
    }
    
    const regex = new RegExp(userPattern);
    return data.filter(item => regex.test(item));
}
```

### 3. "Safe" Regex Libraries (RE2)

```javascript
//  RE2  implementation without catastrophic backtracking
const RE2 = require('re2');  // npm install re2

// Replaces V8's default regex engine with RE2 (Google)
const regex = new RE2('([a-zA-Z]+)*');  // "dangerous" pattern but safe with RE2
console.log(regex.test('aaaaaaaaa!'));  // immediate response, no hanging
```

### 4. Per-Request Timeout

```javascript
//  Preventive protection  timeout on every request
const timeout = require('express-timeout-handler');

app.use(timeout.handler({ timeout: 5000 }));  // 5 seconds maximum
```

---

## 🔗 Chain Exploits

```
ReDoS in email validation at login  DoS the server during traffic peaks
ReDoS on public API + Node.js single-thread  1 request = entire server locked
ReDoS in form input validation  selective DoS (send many requests)
ReDoS in auth middleware  authentication bypass via timeout
```

---

## 📌 References
- [[business-logic-flaws]]
- [[http-security-headers]]
- [ReDoS Checker Online](https://devina.io/redos-checker)
- [Vuln-Regex-Detector](https://github.com/nicowillis/vuln-regex-detector)
- [OWASP ReDoS](https://owasp.org/www-community/attacks/ReDoS)