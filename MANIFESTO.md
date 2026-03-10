# The meda-claw Manifesto

**In an era of centralized AI, governance must be independent.**

---

## The Problem

AI agents now write code, access APIs, handle secrets, and operate autonomously inside enterprise infrastructure. The tools that govern them — attribution, auditing, compliance — are fragmented, proprietary, and controlled by the same companies building the agents.

This is a conflict of interest.

You wouldn't let the defendant run the courtroom. You shouldn't let the AI vendor run the governance stack.

## The Principles

### 1. Independence Over Integration

meda-claw has no vendor affiliation. It doesn't depend on OpenAI, Anthropic, Google, or any AI provider's infrastructure. It runs on your machine, audits your agents, and answers to you.

### 2. Transparency Over Trust

Every component is open-source. The code that audits your code is itself auditable. Tamper-evident hash chains ensure no one — not even the tool operator — can silently alter audit records.

### 3. Privacy Over Telemetry

Zero data leaves your machine. No usage analytics. No cloud dependencies. No "anonymous" metrics. Your governance data is yours.

### 4. Composability Over Lock-in

Each tool works standalone. Use one or use all seven. They're better together but fine alone. No vendor lock-in. No proprietary formats. Standard JSON, standard Git, standard Python.

### 5. Human-in-the-Loop Over Blind Automation

AI can assist. AI cannot self-govern. The Human-Review Attestation system ensures that every AI-heavy contribution has a named human who reviewed it and took responsibility. This isn't bureaucracy — it's accountability.

## The Architecture

```
Attribution  →  Permission  →  Behavior
(Who wrote it?) (What can it access?) (What is it doing?)

git-provenance  →  API_Auditor  →  Agent-Audit
     ↑                  ↑               ↑
     └──────── medaclaw CLI ────────────┘
                    ↓
            Policy-as-Code
         Human-Review Attestation
         Tamper-Evident Audit Chain
```

## The Standard

meda-claw proposes a governance standard for autonomous AI systems:

1. **Every AI contribution must be attributable** — git-provenance tracks what percentage of code is AI-generated and by which model.

2. **Every API key must be audited** — API_Auditor scans for exposed credentials, validates permissions, and quantifies financial exposure.

3. **Every agent action must be logged** — Agent-Audit creates a forensic, tamper-evident record of every file access, command execution, and network request.

4. **Every AI-heavy commit must be human-reviewed** — The attestation system requires cryptographic proof that a human reviewed and approved AI-generated code.

5. **Every governance decision must be auditable** — JSON logs, hash chains, and structured reports make every decision traceable from policy to action.

## Why This Matters

The first wave of AI governance focused on model alignment — making AI say the right things. The second wave is about **operational governance** — ensuring AI does the right things when it has real access to real systems.

meda-claw is built for the second wave.

## Who This Is For

- **Security engineers** who need to audit AI agents in production
- **Compliance teams** who need attestation trails for AI-assisted development
- **Open-source developers** who want governance without vendor lock-in
- **Researchers** studying autonomous agent behavior and accountability
- **Enterprises** evaluating AI governance frameworks

## The Commitment

meda-claw will remain:
- Open-source (AGPL-3.0 for code integrity)
- Independent (no vendor affiliations)
- Privacy-first (zero telemetry, zero cloud)
- Community-driven (contributions welcome)

---

*Built by [Varun Meda](https://github.com/VMaroon95). Not backed by Big Tech. Not funded by VC. Just built because it needed to exist.*

*The watchers need watching. This is how we watch them.*
