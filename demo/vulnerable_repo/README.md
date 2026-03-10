# ⚠️ Vulnerable Demo Repository

**This is a deliberately insecure project for demonstrating meda-claw's detection capabilities.**

All credentials are fake/test values. Do not use any of these in production.

## How to Test

```bash
cd demo/vulnerable_repo
medaclaw report .
```

Expected result: Governance Score well below 50 with multiple critical findings.
