# ShivaAi-Code-Auditor — Cyber Audit Engine

![ShivaAi Banner](assets/banner.png)

## 🛡️ About

**ShivaAi-Code-Auditor** is an **autonomous AI agent** engineered for elite code security auditing and strategic threat intelligence. It operates beyond the scope of a simple plugin or skill — it is a full agentic engine with persistent memory, a structured knowledge vault, a self-evolution cycle, and surgical runtime validation capabilities.

Unlike generic scanners, ShivaAi delivers **offensive-defensive strategy**, deep data-flow correlation, and real-world vulnerability validation anchored exclusively in real code reads. Every finding is evidence-backed. Every claim has an anchor.

> [!NOTE]
> Designed to operate natively within the **Antigravity** ecosystem. The `agents.md` file serves as the engine's initialization briefing, loaded at the start of every new session to restore full operational context.

---

## 🎯 Recommended Model

To ensure maximum technical precision and depth of reasoning:

> [!IMPORTANT]
> **Recommended:** Claude Sonnet 4.6+ or equivalent frontier model with extended thinking.
> Using lower-capability models will compromise the detection of complex multi-file data flows (Source → Sink correlation), autonomous evolution quality, and PoC generation accuracy.

---

## 🚀 Quick Start

1. **Clone:** Download or clone the repository from GitHub.
2. **Activate:** Load the project directory into your **Antigravity** workspace.
3. **Command:** Interact with the engine via the AI terminal using the commands below.

### 💻 Command Interface

| Command | Action |
| :--- | :--- |
| `help` | Full engine manual with all commands and Hybrid Mode explanation |
| `ShivaAuditor -d [path]` | Launch a full audit on the specified project path |
| `ShivaAuditor -d [path] -ip [ip:port]` | Audit in **Hybrid Mode** — enables live HTTP validation against a running target |
| `upgrade` | Trigger the Autonomous Evolution Cycle (self-upgrade of Doctrine + Vault) |

> [!TIP]
> All audit dossiers are automatically generated as `.md` files and saved inside the `reports/` directory upon audit completion.

---

## 🧠 Agentic Intelligence Architecture

ShivaAi operates as a **4-layer autonomous engine**, not a passive tool:

| Layer | Role | Location |
| :--- | :--- | :--- |
| **Layer 1 — Doctrine** | Persistent long-term memory of all tactics, bypasses, and learned patterns | `directives/code-security-analysis.md` |
| **Layer 2 — AI Engine** | Real-time code reading, cross-file correlation, and exploit reasoning | *(you — the LLM runtime)* |
| **Layer 3 — Ad-Hoc Tooling** | Ephemeral Python scripts for surgical runtime validation (SQLi, LFI, JWT, etc.) | `.tmp/` *(discarded after use)* |
| **Layer 4 — Security Vault** | 70+ tactical knowledge files covering every major vulnerability class and stack | `security-vault/` |

---

## 🔬 Core Operational Protocols

The engine enforces strict internal protocols to maintain analysis integrity:

- **Data Flow Ledger (`[DATA FLOW CHECKPOINT]`):** Mandatory structured tracking of tainted variables across files. The engine is *forbidden* from jumping between files without emitting an explicit checkpoint documenting the variable's origin, transformations, and taint status.
- **Anti-Hallucination Gate (DNA Rule):** Every vulnerability claim must pass two tests — the *Real Evidence Test* (anchored in actual code or a functional PoC) and the *False Positive Prevention Clause* (explicit reasoning on what the safe equivalent looks like).
- **Execution Modes:**
  - **Offline Mode** — Purely static analysis. All findings labeled "Confirmed by Static Analysis" or "Requires Runtime Validation".
  - **Hybrid Mode** — Code + running target. Ephemeral scripts confirm findings at runtime before they enter the dossier.
- **Phase 0 (Surface Mapping — MANDATORY):** Before any vulnerability hunt, the engine maps all entry points, auth/authz middleware boundaries, and data models. No deep dive begins without a "Treasure Map".

---

## ♻️ Autonomous Evolution Cycle

The `upgrade` command triggers a privileged self-maintenance routine:

1. Read the current Doctrine and all Vault files in their entirety.
2. Apply the **Rule of Depth**: refine existing intelligence before adding new vectors.
3. Apply the **Anti-Hallucination Gate** to all proposed additions.
4. Write improvements to the Doctrine and/or Vault tactical files.
5. Advance the semantic version by **+0.1** and commit with a structured message.

> [!WARNING]
> Major version jumps (e.g., v1.x → v2.0) are **strictly forbidden** without explicit user authorization. The evolution cycle is autonomous but disciplined.

---

## ⚠️ Important Caveats

> [!CAUTION]
> **No static analysis is infallible.** The audit dossier must be treated as **actionable intelligence for human investigation**, not as ground truth. The senior auditor is responsible for:
> - Validating the evidence anchors cited in each finding.
> - Cross-referencing with Hybrid Mode validation where possible.
> - Ruling out false positives using the False Positive Prevention Clauses documented in the Vault.

---

## 📁 Ecosystem Structure

```
agents.md         # Engine initialization briefing — loaded every session.
directives/       # Living Doctrine — persistent memory of all learned tactics.
security-vault/   # 70+ tactical knowledge files covering every major vuln class.
reports/          # Audit dossiers (.md) auto-generated per project.
.tmp/             # Ephemeral Python validation scripts — created and discarded per audit.
examples/         # Training and demonstration targets.
```

---

## ⚖️ Golden Principle

> You absorb the code, anchor every claim in real evidence, build the exploit if you need to prove it, and dictate the dossier.
> **You are the auditor. Do not speculate without an anchor. Do not stop until all avenues are exhausted.**

---

<p align="center">
  <i>Developed by <b><a href="https://github.com/pedrosilvaevangelista">Pinkman</a></b></i>
</p>
