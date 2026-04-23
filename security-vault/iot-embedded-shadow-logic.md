# IoT & Embedded Shadow Logic — Tactical Pillar

> **Context:** High-level code (Node.js, Python, C#) that interacts with embedded systems, hardware interfaces, or IoT devices often harbors "C-style" hardware vulnerabilities, legacy backdoor mechanisms, and insecure update lifecycles.

---

## 1. Diagnostic Mode Backdoors (Shadow Logic)
- **Scenario:** Developers leave hardcoded routines active for factory testing or debugging hardware state.
- **Tactic:** Attacker sends a specific undocumented byte sequence (`0xDEADBEEF`) or API parameter (`?diag_mode=1`) that bypasses all software authentication and opens a direct serial shell.
- **`grep_search`:** `diag_mode`, `factory_reset`, `test_mode`, `0x`, `magic_bytes`.

## 2. Unsafe Buffer Parsing
- **Scenario:** IoT communication often relies on raw TCP/UDP sockets or Serial ports where data is extracted using bitwise operations or raw buffer slicing.
- **Tactic:** The lack of length validation leads to buffer over-reads or logic failures when parsing payloads like MQTT packets or CoAP messages.
- **`grep_search`:** `Buffer.allocUnsafe(`, `struct.unpack(`, `serial.write(`, `buffer.copy(`.

## 3. Cleartext Serial & Bus Communication
- **Scenario:** Secure web layers (WSS, HTTPS) terminate at an edge controller which then communicates with the internal hardware via unencrypted I2C, SPI, or UART.
- **Tactic:** If an attacker gains low-privileged execution on the edge controller, they sniff or tamper with the raw unencrypted hardware communication bus.
- **`grep_search`:** `I2C`, `SPI`, `UART`, `baudrate`.

## 4. Insecure Over-The-Air (OTA) Updates
- **Scenario:** The device pulls firmware updates from a server without cryptographic signature verification.
- **Tactic:** Attacker intercepts the DNS or HTTP request and serves a maliciously compiled firmware. The device installs the backdoor, leading to permanent hardware compromise.
- **`grep_search`:** `ota_update`, `firmware_url`, `verifySignature(`, `md5` (used for integrity instead of ECDSA).

## 5. MQTT Topic Manipulation (Wildcard Hijacking)
- **Scenario:** Devices subscribe or publish to MQTT brokers using wildcards (`#` or `+`) without strict ACLs.
- **Tactic:** Attacker publishes to `#` or an administrative topic, broadcasting malicious commands to all fleet devices simultaneously.
- **`grep_search`:** `mqtt.subscribe`, `+`, `#`, `broker.publish`.

## Strategic Checklist
1. [ ] Search for undocumented flags in the parsers.
2. [ ] Audit buffer length validation in hardware-interfacing methods.
3. [ ] Review MQTT, CoAP, and direct socket bindings for TLS usage and Topic ACLs.
4. [ ] Validate that OTA updates require asymmetric cryptographic signatures (e.g., ECDSA), not just MD5/SHA256 hashes.

---
*Tags: #iot #embedded #hardware #buffer #ota #mqtt #shiva-vault*
