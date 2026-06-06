# Memory Management Failures

**Tags:** #critical #memory #buffer-overflow #use-after-free #c #cpp
**OWASP:** X02:2025 Memory Management Failures
**CVSS Base:** 9.8 (Critical — Buffer Overflow can lead to RCE)

---

## 📖 What is it

Memory management failures occur when programs written in non-memory-safe languages (C, C++) make errors when allocating, accessing, or freeing memory. These vulnerabilities frequently achieve the highest CVSS scores because they directly enable arbitrary code execution, data exfiltration, and full system compromise.

> **Memory-Safe languages (immune to this class):** Rust, Java, Go, C#, Python, Swift, Kotlin, JavaScript

---

## 🔍 `grep_search` Tactics

```
# Classic buffer overflows
strcpy(
strcat(
sprintf(
gets(
scanf(

# Prefer these instead (safe variants)
strncpy(
strncat(
snprintf(

# Use-After-Free / Double Free indicators
free(ptr)
delete ptr
ptr = NULL  # Was this done AFTER free? (If not, UAF risk)

# Format String attacks
printf(user_input)
syslog(user_input)
fprintf(stream, user_input)

# Memory leak indicators
malloc(
calloc(
new
# without a corresponding free() or delete in all code paths
```

---

## 💣 Vulnerability Patterns & Scenarios

### 1. Classic Buffer Overflow (CWE-120 / CWE-121 — OWASP Scenario #1)
An attacker submits more data than the buffer can hold, overwriting adjacent memory — typically the stack return pointer — and redirecting execution to attacker-controlled shellcode.

```c
//  VULNERABLE — strcpy has no length limit
void process_input(char *user_input) {
    char buf[64];
    strcpy(buf, user_input); // If user_input > 64 bytes → stack overflow
}

//  CORRECT — strncpy with explicit size limit
void process_input(char *user_input) {
    char buf[64];
    strncpy(buf, user_input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0'; // Ensure null terminator
}
```

**Exploit chain:** Overflow the stack → Overwrite return address → Jump to shellcode → RCE.

### 2. Use-After-Free (UAF) (CWE-416 — OWASP Scenario #2)
Memory is freed but the pointer is not set to `NULL`. The attacker manipulates the allocator to place attacker-controlled data at the same memory address. When the dangling pointer is later used, it executes the attacker's data as code or data.

```c
//  VULNERABLE — Dangling pointer
char *ptr = malloc(100);
free(ptr);
// ptr is now a "dangling pointer" pointing to freed memory!

// If attacker can cause a new allocation to reuse this address...
strncpy(ptr, attacker_data, 99); // Writing to freed memory → UAF exploit
```

**Real-world context:** A common browser bug bounty class. Browsers are hardened with ASLR, DEP, and sandboxing, making exploitation non-trivial.

```c
//  CORRECT — Nullify after free
free(ptr);
ptr = NULL; // Now any subsequent dereference causes a clean crash, not silent UAF
```

### 3. Format String Attack (CWE-134 — OWASP Scenario #3)
When user input is passed *as the format string* to `printf`-family functions, the attacker uses `%x` to read stack memory or `%n` to write to arbitrary memory.

```c
//  VULNERABLE — User input IS the format string
char *user_input = req.body; // e.g., "%x %x %x %x %n"
printf(user_input);          // Reads stack memory / writes to arb. address!

//  CORRECT — User input is an ARGUMENT, not the format string
printf("%s", user_input);    // Always use a literal format string
```

**PoC Payload:** `%x.%x.%x.%x` → Dumps 4 stack values as hex (useful for ASLR bypass).

### 4. Integer Overflow → Buffer Overflow (CWE-190)
An integer overflow causes a size calculation to wrap around to a very small number, causing `malloc` to allocate a tiny buffer while the code assumes it is large.

```c
//  VULNERABLE — Integer overflow in size calculation
size_t n = user_supplied_count;  // e.g., n = 0x40000001
size_t total = n * sizeof(int);  // OVERFLOW: 0x40000001 * 4 = 4 (wraps around!)
int *arr = malloc(total);        // Allocates 4 bytes instead of gigabytes
arr[5] = user_value;             // Heap overflow!

//  CORRECT — Check for overflow before allocation
if (n > SIZE_MAX / sizeof(int)) { abort(); } // Prevent overflow
int *arr = malloc(n * sizeof(int));
```

---

## 🛡️ Defensive Architecture

| Mitigation | Description |
|---|---|
| **ASLR** (Address Space Layout Randomization) | Randomizes where code/heap/stack are in memory. Makes hard-coded addresses fail. |
| **DEP/NX** (Data Execution Prevention) | Marks the stack and heap as non-executable. Prevents classic shellcode injection. |
| **Stack Canaries** | Compiler places a "canary" value before the return address. If the canary changes, the program aborts before RCE. |
| **RELRO + PIE** | Hardens GOT/PLT sections and randomizes executable base address. |
| **Safe Functions** | `strncpy` over `strcpy`, `snprintf` over `sprintf`, `fgets` over `gets`. |

---

## 🔗 Chain Exploits

```
Buffer Overflow → Overwrite return pointer → Shellcode execution → Root RCE
UAF (Browser) → Heap spray → Control flow hijack → Sandbox escape
Integer Overflow → malloc underallocation → Heap corruption → Privilege escalation
Format String → ASLR leak → Buffer Overflow → Full RCE chain
```

---

## 📌 References
- [[application-resilience-dos]]
- [Project Zero Blog](https://googleprojectzero.blogspot.com/)
- [OWASP Memory leak](https://owasp.org/www-community/vulnerabilities/Memory_leak)
- [OWASP Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
