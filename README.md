# ShivaAi-Code-Auditor — Cyber Audit Engine

![ShivaAi Banner](assets/banner.png)

## 🛡️ About

**ShivaAi-Code-Auditor** is an **autonomous AI agent** engineered for elite code security auditing and strategic threat intelligence. It operates beyond the scope of a simple plugin or skill — it is a full agentic engine with persistent memory, a structured knowledge vault, a self-evolution cycle, and surgical runtime validation capabilities.

Unlike generic scanners, ShivaAi delivers **offensive-defensive strategy**, deep data-flow correlation, and real-world vulnerability validation anchored exclusively in real code reads. Every finding is evidence-backed. Every claim has an anchor.

> [!IMPORTANT]
> Designed **exclusively** to operate natively within the **Antigravity** ecosystem. The `AGENTS.md` file serves as the engine's initialization briefing, loaded at the start of every new session to restore full operational context.

---

## 🚀 How to Use ShivaAi

1. **Load the Agent:** Open this project directory inside your **Antigravity** workspace.
2. **Command:** Interact with the engine via the AI terminal using the commands below.
3. **Review the Dossier:** Upon audit completion, the dossier is automatically saved to the `reports/` directory as a structured `.md` file.

### 💻 Command Interface

| Command | Action |
| :--- | :--- |
| `help` | Full engine manual with all commands and Hybrid Mode explanation |
| `ShivaAuditor -d [path]` | Launch a full audit on the specified project path |
| `ShivaAuditor -d [path] -ip [ip:port]` | Audit in **Hybrid Mode** — enables live HTTP validation against a running target |
| `upgrade` | Trigger the Autonomous Evolution Cycle (self-upgrade of Doctrine + Vault) |

---

## 🧠 Architecture

ShivaAi operates as a **4-layer autonomous engine**:

| Layer | Role | Location |
| :--- | :--- | :--- |
| **Layer 1 — Doctrine** | Persistent memory of all tactics, bypasses, and learned patterns | `directives/code-security-analysis.md` |
| **Layer 2 — AI Engine** | Real-time code reading, cross-file correlation, and exploit reasoning | *(you — the LLM runtime)* |
| **Layer 3 — Ad-Hoc Tooling** | Ephemeral Python scripts for surgical runtime validation (SQLi, LFI, JWT, etc.) | `.tmp/` *(discarded after use)* |
| **Layer 4 — Security Vault** | 70+ tactical knowledge files covering every major vulnerability class and stack | `security-vault/` |

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

## 📁 Ecosystem Structure

```
AGENTS.md         # Engine initialization briefing — loaded every session.
directives/       # Living Doctrine — persistent memory of all learned tactics.
security-vault/   # 70+ tactical knowledge files covering every major vuln class.
reports/          # Audit dossiers (.md) auto-generated per project.
.tmp/             # Ephemeral Python validation scripts — created and discarded per audit.
examples/         # Training and demonstration targets.
```

---

## 🎯 Recommended Model

> [!WARNING]
> **Recommended:** Claude Sonnet 4.6+ or equivalent frontier model with extended thinking.
> Using lower-capability models will compromise multi-file data-flow correlation (Source → Sink), autonomous evolution quality, and PoC generation accuracy.

---

## ⚖️ Golden Principle

> You absorb the code, anchor every claim in real evidence, build the exploit if you need to prove it, and dictate the dossier.
> **You are the auditor. Do not speculate without an anchor. Do not stop until all avenues are exhausted.**

---

<p align="center">
  <i>Developed by <b><a href="https://github.com/pedrosilvaevangelista">Pinkman</a></b></i>
</p>
