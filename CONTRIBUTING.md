# Contributing to meda-claw

Thank you for your interest in contributing to meda-claw. This project maintains high standards for code quality, security, and academic rigor.

## Current Priorities

We are actively seeking core contributors for:

- **Agent Behavior Module** — Expanding Agent-Audit with process-level monitoring (ptrace/DTrace), anomaly detection via behavioral baselines, and multi-agent session correlation.
- **Legal Signatures Module** — Extending the Human-Review Attestation system with GPG signing, OIDC-based identity verification, and integration with enterprise SSO.
- **SIEM Integration** — Splunk, Elastic, and Grafana connectors for enterprise deployment.
- **Benchmarking** — Expanding the Proof-of-Audit benchmark suite with adversarial scenarios.

## Standards

### Code Quality

- **Python 3.10+** with full type hints
- **Zero external dependencies** for core modules (click and colorama are the only CLI deps)
- **Pure stdlib** where possible — no heavy frameworks
- All functions must include docstrings explaining purpose, parameters, and return values
- Follow existing code patterns and naming conventions

### Security

- No secrets, tokens, or credentials in code — ever
- No telemetry, analytics, or network calls from core modules
- All audit data must be tamper-evident (hash-chained)
- External inputs must be validated and sanitized

### Testing

- Every new feature requires corresponding test coverage
- Benchmark scenarios for security-critical features
- Edge cases must be explicitly tested (empty inputs, malformed data, adversarial inputs)

### Commits

- Practice what we preach: use `medaclaw sign` on AI-assisted contributions
- Clear, descriptive commit messages
- One logical change per commit
- Reference related issues where applicable

## Process

1. **Fork** the repository
2. **Create a branch** from `main` (`feature/your-feature` or `fix/your-fix`)
3. **Write code** following the standards above
4. **Test** thoroughly — run `medaclaw benchmark` to verify nothing breaks
5. **Sign** your work if AI-assisted: `medaclaw sign --reviewer "Your Name" --ai-pct <percentage>`
6. **Submit a PR** with a clear description of what and why

## What Makes a Good Contribution

- Solves a real problem in AI governance or agent security
- Maintains the independence principle (no vendor dependencies)
- Includes documentation and examples
- Is security-conscious by default
- Could be cited in an academic paper

## What We Won't Accept

- Code that phones home or adds telemetry
- Vendor-specific integrations that create lock-in
- Breaking changes without migration paths
- PRs without tests for security-critical code
- AI-generated code without human review attestation

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license. For questions about commercial licensing, contact varunmeda95@gmail.com.

## Contact

- **Maintainer:** Varun Meda — [GitHub](https://github.com/VMaroon95) · [LinkedIn](https://linkedin.com/in/varunmeda1)
- **Issues:** [github.com/VMaroon95/meda-claw/issues](https://github.com/VMaroon95/meda-claw/issues)

---

*We're building the governance standard for autonomous AI. If that matters to you, we want you here.*
