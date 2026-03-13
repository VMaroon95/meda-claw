# 🦞 Contributing to medaclaw

First, thank you for being part of the mission to secure the Agentic Era. `medaclaw` is a sovereign framework, and we maintain high standards for the logic that enters our core engine.

## 🏛️ The Sovereign Rules of Contribution

To protect the integrity and vision of the project, all contributors must adhere to the following:

### 1. Architectural Authority
`medaclaw` is guided by a specific "Meda-Risk" philosophy. Before writing any major code:
- **Open an Issue:** Discuss your proposed changes with the Lead Architect.
- **Approval:** No architectural shifts will be merged without explicit sign-off from the project lead.

### 2. Attribution & Credit
Your hard work will be recognized, but the project identity remains unified:
- **Contributors List:** Significant contributions will be added to a `CONTRIBUTORS.md` file.
- **Copyright:** All contributions are made under the existing **AGPL-3.0 License**. By contributing, you agree that your code will be governed by this license to keep the project open and protected.

### 3. Technical Standards (The "Hardened" Rule)
We do not accept "guesswork" logic. Any new scanners or behavioral rules must:
- Use **AST (Abstract Syntax Tree)** analysis where possible (refer to `behavior.py`).
- Include a test case that proves detection of a specific "hallucinated" AI vulnerability.
- Maintain the performance threshold (< 2s for standard repositories).

## 🛡️ How to Get Started
1. Fork the repo (for your own development).
2. Create a feature branch (`git checkout -b feature/hardened-logic`).
3. Commit your changes.
4. Open a Pull Request for review.

**Note:** The Lead Architect reserves the right to request changes or reject PRs that do not align with the security standards of the Project Sovereign vision.
