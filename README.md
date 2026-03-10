# 🦞 meda-claw

**The Independent AI Governance & Security Stack**

In an era of centralized AI platforms, `meda-claw` is the open-source standard for AI security, IP provenance, and financial auditing. One CLI to govern them all.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

> 📜 Read the [Manifesto](MANIFESTO.md) — why independent AI governance matters.

---

## The Problem

AI agents write your code, access your APIs, and operate in your infrastructure. But governance is fragmented — different tools for attribution, permissions, behavior, and compliance, with no unified control plane.

**meda-claw** solves this by orchestrating a complete governance stack from a single CLI.

## The Stack

```
┌─────────────────────────────────────────────────────────┐
│                    medaclaw CLI                          │
│              Unified Governance Interface                │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│ 🔍       │ 🔐       │ 🔑       │ 🔬       │ ⚡          │
│ Agent    │ Git      │ API      │ Repo     │ Project     │
│ Audit    │ Prove-   │ Auditor  │ X-Ray    │ Spark       │
│          │ nance    │          │          │             │
│ Behavior │ IP &     │ Keys &   │ AST &    │ LLM Eval   │
│ Scoring  │ Attrib.  │ Finance  │ Secrets  │ & CLEAR Act │
├──────────┴──────────┴──────────┴──────────┴─────────────┤
│ 🛡️ ExtensionGuard          │ 🔔 Push Guardian           │
│ Browser Extension Security  │ Notification Sanitization  │
└─────────────────────────────┴───────────────────────────┘
```

### The Governance Triad

| Layer | Tool | What It Governs |
|-------|------|-----------------|
| **Attribution** | Git_Provenance | Who wrote the code — human or AI? IP compliance & audit trails |
| **Permissions** | API_Auditor | What keys are exposed? Financial risk from API misconfiguration |
| **Behavior** | Agent-Audit | What is the agent doing? Real-time forensic monitoring & risk scoring |

**Provenance → Permission → Performance** — Full-stack governance for the agent era.

## Quick Start

```bash
# Install
pip install meda-claw

# Or from source
git clone https://github.com/VMaroon95/meda-claw.git
cd meda-claw
pip install -e .

# Initialize in a project
medaclaw init ./my-project

# Full security scan
medaclaw scan ./my-project

# Behavioral audit (demo)
medaclaw audit --demo

# Activate IP & financial safeguards
medaclaw protect ./my-project

# Check suite health
medaclaw status
```

## Commands

### `medaclaw audit`
Runs Agent-Audit (behavioral risk scoring) and Repo_X-Ray (AST analysis) for comprehensive agent + code auditing.

```bash
medaclaw audit ./project                    # Audit a directory
medaclaw audit --demo                       # Run demo with simulated actions
medaclaw audit --policy strict.json ./proj  # Custom policy
```

### `medaclaw protect`
Activates Git_Provenance hooks (AI attribution gating) and API_Auditor (key permission scanning).

```bash
medaclaw protect ./project                  # Default protection
medaclaw protect --threshold 50 ./project   # 50% AI contribution limit
medaclaw protect --providers aws,stripe     # Scan specific providers
```

### `medaclaw scan`
Full security scan — secrets, credentials, API keys, configuration files.

```bash
medaclaw scan ./project          # Quick scan
medaclaw scan --deep ./project   # Include AST + dependency analysis
```

### `medaclaw evaluate`
LLM benchmark & CLEAR Act compliance checking via ProjectSpark.

```bash
medaclaw evaluate --model gpt-4     # Evaluate a model
medaclaw evaluate --compliance       # Run compliance check
```

### `medaclaw init`
Initialize meda-claw governance in any project. Creates config, git hooks, and directory structure.

```bash
medaclaw init ./my-project          # Basic init
medaclaw init --full ./my-project   # Clone all components locally
```

### `medaclaw status`
Dashboard showing which components are installed and their last commit.

## Project Structure

```
meda-claw/
├── meda_claw/
│   ├── __init__.py
│   ├── cli.py              # Unified CLI
│   └── wrappers/           # Component integration
├── setup.py
├── pyproject.toml
├── LICENSE
└── README.md
```

## Component Repos

Each component is a standalone tool that also works independently:

| Component | Repository | Focus |
|-----------|-----------|-------|
| 🔍 Agent-Audit | [VMaroon95/Agent-Audit](https://github.com/VMaroon95/Agent-Audit) | Behavioral auditing of AI agents |
| 🔐 Git_Provenance | [VMaroon95/Git_Provenance](https://github.com/VMaroon95/Git_Provenance) | AI attribution & IP compliance |
| 🔑 API_Auditor | [VMaroon95/API_Auditor](https://github.com/VMaroon95/API_Auditor) | API key permission & financial auditing |
| 🔬 Repo_X-Ray | [VMaroon95/Repo_X-Ray](https://github.com/VMaroon95/Repo_X-Ray) | AST security scanner & dependency graphs |
| ⚡ ProjectSpark | [VMaroon95/ProjectSpark](https://github.com/VMaroon95/ProjectSpark) | LLM evaluation & CLEAR Act compliance |
| 🛡️ ExtensionGuard | [VMaroon95/ExtensionGuard](https://github.com/VMaroon95/ExtensionGuard) | Browser extension security suite |
| 🔔 Push_Guardian | [VMaroon95/Push_Guardian](https://github.com/VMaroon95/Push_Guardian) | Push notification sanitization |

## Research

This platform supports ongoing doctoral research:

> **"Autonomous Platform Governance: A Unified Framework for AI Attribution, Permission Auditing, and Behavioral Forensics in Enterprise Agent Systems"**

Exploring how a composable, open-source governance stack can replace fragmented proprietary solutions for enterprise AI agent deployment. See individual component repos for specific research abstracts.

## Philosophy

- **Independent** — No vendor lock-in. Every component works standalone.
- **Open-source** — MIT licensed. Audit the code that audits your code.
- **Privacy-first** — All processing is local. Zero telemetry. Zero cloud dependencies.
- **Composable** — Use one tool or all seven. They're better together but fine alone.

## Proof of Audit

Don't trust — verify. Run the benchmark to see meda-claw catch real threats:

```bash
medaclaw benchmark
```

Three scenarios, three catches, zero false negatives:

1. **Secret Exfiltration** — Plants dummy AWS/GitHub/OpenAI keys → scanner catches all 3
2. **Unsigned AI Commit** — 85% AI code without attestation → policy engine blocks it
3. **Attestation Tampering** — Modifies a signed attestation → integrity check detects it

```
  🎯 PERFECT SCORE — All threats detected.
     meda-claw governance stack is operational.
```

## Contributing

We're seeking core contributors for the **Agent Behavior** and **Legal Signatures** modules.

See [CONTRIBUTING.md](CONTRIBUTING.md) for standards and process.

## Roadmap

- [ ] PyPI package publication
- [ ] Unified dashboard (web UI)
- [ ] SIEM integration (Splunk, Elastic)
- [ ] GitHub Actions workflow templates
- [ ] Docker deployment
- [ ] VS Code extension
- [ ] Enterprise policy templates

## License

AGPL-3.0 — see [LICENSE](LICENSE). Commercial licensing available for enterprise/SaaS deployment (contact varunmeda95@gmail.com).

## Author

**Varun Meda** — [GitHub](https://github.com/VMaroon95) · [LinkedIn](https://linkedin.com/in/varunmeda1)

---

*In an era of centralized AI, meda-claw is the independent, open-source standard for AI governance.*
