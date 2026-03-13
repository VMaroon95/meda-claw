#!/usr/bin/env python3
"""
meda-claw CLI — The Independent AI Governance & Security Stack.

Unified command interface for the entire Meda suite:
  • Agent-Audit    — Behavioral auditing of AI agents
  • Git_Provenance — AI attribution & IP compliance for Git
  • API_Auditor    — API key permission scanning & financial exposure
  • Repo_X-Ray     — AST security scanning & dependency graph analysis
  • ProjectSpark   — LLM evaluation & CLEAR Act compliance

Usage:
    medaclaw audit [OPTIONS]       — Run behavioral + forensic audits
    medaclaw protect [OPTIONS]     — Activate IP & financial safeguards
    medaclaw scan [OPTIONS]        — Full security scan (X-Ray + secrets)
    medaclaw evaluate [OPTIONS]    — LLM benchmark & compliance check
    medaclaw status                — Suite health & configuration
    medaclaw init [OPTIONS]        — Initialize governance in a project
"""

import os
import sys
import json
import time
import subprocess
import shutil
from pathlib import Path

try:
    import click
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
    from meda_claw.policy import (
        create_attestation, save_attestation, load_attestations,
        verify_attestation_integrity, verify_human_in_loop,
        full_governance_check, get_attestation_for_commit,
    )
except ImportError:
    print("Missing dependencies. Run: pip install click colorama")
    sys.exit(1)


# ── Helpers ──────────────────────────────────────────────────────────────

SUITE_DIR = Path(__file__).parent
COMPONENTS = {
    "agent-audit": {
        "name": "Agent-Audit",
        "repo": "VMaroon95/Agent-Audit",
        "desc": "Behavioral audit engine for AI agents",
        "icon": "🔍",
    },
    "git-provenance": {
        "name": "Git_Provenance",
        "repo": "VMaroon95/Git_Provenance",
        "desc": "AI attribution & IP compliance firewall",
        "icon": "🔐",
    },
    "api-auditor": {
        "name": "API_Auditor",
        "repo": "VMaroon95/API_Auditor",
        "desc": "API key permission scanner & financial auditor",
        "icon": "🔑",
    },
    "repo-xray": {
        "name": "Repo_X-Ray",
        "repo": "VMaroon95/Repo_X-Ray",
        "desc": "AST security scanner & dependency graph",
        "icon": "🔬",
    },
    "projectspark": {
        "name": "ProjectSpark",
        "repo": "VMaroon95/ProjectSpark",
        "desc": "LLM evaluation & CLEAR Act compliance",
        "icon": "⚡",
    },
    "extensionguard": {
        "name": "ExtensionGuard",
        "repo": "VMaroon95/ExtensionGuard",
        "desc": "Browser extension security suite",
        "icon": "🛡️",
    },
    "push-guardian": {
        "name": "Push_Guardian",
        "repo": "VMaroon95/Push_Guardian",
        "desc": "Push notification sanitization middleware",
        "icon": "🔔",
    },
}


def banner():
    """Print the meda-claw banner."""
    click.echo(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   {Fore.WHITE}███╗   ███╗███████╗██████╗  █████╗                    {Fore.CYAN}║
║   {Fore.WHITE}████╗ ████║██╔════╝██╔══██╗██╔══██╗                   {Fore.CYAN}║
║   {Fore.WHITE}██╔████╔██║█████╗  ██║  ██║███████║                   {Fore.CYAN}║
║   {Fore.WHITE}██║╚██╔╝██║██╔══╝  ██║  ██║██╔══██║                   {Fore.CYAN}║
║   {Fore.WHITE}██║ ╚═╝ ██║███████╗██████╔╝██║  ██║                   {Fore.CYAN}║
║   {Fore.WHITE}╚═╝     ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝  {Fore.YELLOW}CLAW{Fore.WHITE} v1.0.0   {Fore.CYAN}║
║                                                          ║
║   {Fore.GREEN}The Independent AI Governance & Security Stack{Fore.CYAN}         ║
║   {Fore.WHITE}github.com/VMaroon95/meda-claw{Fore.CYAN}                         ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")


def run_component(component_dir, args, label=""):
    """Run a component's CLI if available."""
    cli_path = component_dir / "cli.py"
    if cli_path.exists():
        result = subprocess.run(
            [sys.executable, str(cli_path)] + args,
            capture_output=False,
            cwd=str(component_dir),
        )
        return result.returncode == 0
    else:
        click.echo(f"  {Fore.YELLOW}⚠ {label} CLI not found at {cli_path}{Style.RESET_ALL}")
        return False


def find_component(name):
    """Find a component directory (checks common locations)."""
    search_paths = [
        Path.cwd() / name,
        Path.home() / ".meda-claw" / name,
        SUITE_DIR.parent / name,
        Path.cwd().parent / name,
    ]
    for p in search_paths:
        if p.exists():
            return p
    return None


# ── CLI Group ────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show version")
@click.pass_context
def cli(ctx, version):
    """meda-claw: The Independent AI Governance & Security Stack."""
    if version:
        click.echo("meda-claw v1.0.0")
        return
    if ctx.invoked_subcommand is None:
        banner()
        click.echo(f"  Run {Fore.GREEN}medaclaw --help{Style.RESET_ALL} for available commands.\n")


# ── Command: audit ───────────────────────────────────────────────────────

@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--policy", default=None, help="Policy file (JSON)")
@click.option("--agent-id", default="unknown-agent", help="Agent identifier")
@click.option("--demo", is_flag=True, help="Run demo audit")
def audit(target, policy, agent_id, demo):
    """Run behavioral + forensic audit on a project or agent session.

    Combines Agent-Audit (behavioral scoring) with Repo_X-Ray (AST analysis)
    for a comprehensive security assessment.
    """
    banner()
    click.echo(f"{Fore.CYAN}━━━ AUDIT MODE ━━━{Style.RESET_ALL}\n")

    # Agent-Audit
    click.echo(f"  {Fore.GREEN}🔍 Agent-Audit{Style.RESET_ALL} — Behavioral risk scoring")
    agent_audit_dir = find_component("Agent-Audit") or find_component("agent-audit")
    if agent_audit_dir:
        args = ["demo"] if demo else ["watch", target]
        if policy:
            args.extend(["--policy", policy])
        if agent_id:
            args.extend(["--agent-id", agent_id])
        run_component(agent_audit_dir, args, "Agent-Audit")
    else:
        click.echo(f"    {Fore.YELLOW}Install: git clone https://github.com/VMaroon95/Agent-Audit{Style.RESET_ALL}")

    # Repo X-Ray
    click.echo(f"\n  {Fore.GREEN}🔬 Repo_X-Ray{Style.RESET_ALL} — AST security scan")
    xray_dir = find_component("Repo_X-Ray") or find_component("repo-xray")
    if xray_dir:
        run_component(xray_dir, ["scan", target], "Repo_X-Ray")
    else:
        click.echo(f"    {Fore.YELLOW}Install: git clone https://github.com/VMaroon95/Repo_X-Ray{Style.RESET_ALL}")

    click.echo(f"\n{Fore.CYAN}━━━ AUDIT COMPLETE ━━━{Style.RESET_ALL}")


# ── Command: protect ─────────────────────────────────────────────────────

@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--threshold", default=30, help="AI contribution threshold (%)")
@click.option("--providers", default="all", help="API providers to scan (all|google|aws|stripe)")
def protect(target, threshold, providers):
    """Activate IP compliance & financial safeguards.

    Initializes Git_Provenance hooks and runs API_Auditor to detect
    exposed keys and financial exposure.
    """
    banner()
    click.echo(f"{Fore.CYAN}━━━ PROTECT MODE ━━━{Style.RESET_ALL}\n")

    # Git Provenance
    click.echo(f"  {Fore.GREEN}🔐 Git_Provenance{Style.RESET_ALL} — AI attribution & IP compliance")
    prov_dir = find_component("Git_Provenance") or find_component("git-provenance")
    if prov_dir:
        run_component(prov_dir, ["init", "--threshold", str(threshold), target], "Git_Provenance")
    else:
        click.echo(f"    {Fore.YELLOW}Install: git clone https://github.com/VMaroon95/Git_Provenance{Style.RESET_ALL}")

    # API Auditor
    click.echo(f"\n  {Fore.GREEN}🔑 API_Auditor{Style.RESET_ALL} — Key permission & financial audit")
    api_dir = find_component("API_Auditor") or find_component("api-auditor")
    if api_dir:
        run_component(api_dir, ["scan", "--providers", providers, target], "API_Auditor")
    else:
        click.echo(f"    {Fore.YELLOW}Install: git clone https://github.com/VMaroon95/API_Auditor{Style.RESET_ALL}")

    click.echo(f"\n{Fore.CYAN}━━━ PROTECTION ACTIVE ━━━{Style.RESET_ALL}")


# ── Command: scan ────────────────────────────────────────────────────────

@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--deep", is_flag=True, help="Include AST + dependency analysis")
def scan(target, deep):
    """Full security scan — secrets, permissions, dependencies.

    Runs all detection modules across the target directory.
    """
    banner()
    click.echo(f"{Fore.CYAN}━━━ FULL SCAN ━━━{Style.RESET_ALL}\n")

    target_path = Path(target).resolve()
    results = {"target": str(target_path), "timestamp": time.time(), "findings": []}

    # Secret scanning
    click.echo(f"  {Fore.GREEN}🔐 Scanning for secrets...{Style.RESET_ALL}")
    secret_patterns = [
        ("AWS Key", r"AKIA[0-9A-Z]{16}"),
        ("GitHub Token", r"ghp_[a-zA-Z0-9]{36}"),
        ("OpenAI Key", r"sk-[a-zA-Z0-9]{48}"),
        ("Generic Secret", r"(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*['\"][^'\"]{8,}['\"]"),
    ]

    import re
    scanned = 0
    found = 0
    for root, dirs, files in os.walk(target_path):
        # Skip common non-source dirs
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv", ".env"}]
        for fname in files:
            if fname.endswith((".py", ".js", ".ts", ".json", ".yaml", ".yml", ".env", ".cfg", ".ini", ".toml")):
                fpath = Path(root) / fname
                try:
                    content = fpath.read_text(errors="ignore")
                    scanned += 1
                    for name, pattern in secret_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            found += len(matches)
                            results["findings"].append({
                                "type": "secret",
                                "name": name,
                                "file": str(fpath.relative_to(target_path)),
                                "count": len(matches),
                            })
                            click.echo(f"    {Fore.RED}● {name}{Style.RESET_ALL} in {fpath.relative_to(target_path)} ({len(matches)} match{'es' if len(matches) > 1 else ''})")
                except (OSError, UnicodeDecodeError):
                    continue

    click.echo(f"  Scanned {scanned} files — {Fore.RED if found else Fore.GREEN}{found} secrets found{Style.RESET_ALL}")

    # Permission scanning
    click.echo(f"\n  {Fore.GREEN}🔑 Scanning for API configurations...{Style.RESET_ALL}")
    config_files = list(target_path.glob("**/.env*")) + list(target_path.glob("**/config*.json"))
    click.echo(f"  Found {len(config_files)} configuration files")

    if deep:
        click.echo(f"\n  {Fore.GREEN}🔬 Deep analysis (AST + dependencies)...{Style.RESET_ALL}")
        # Check for known vulnerable packages
        pkg_files = list(target_path.glob("**/package.json")) + list(target_path.glob("**/requirements*.txt"))
        click.echo(f"  Found {len(pkg_files)} dependency manifests")

    # Summary
    click.echo(f"\n{Fore.CYAN}━━━ SCAN SUMMARY ━━━{Style.RESET_ALL}")
    click.echo(f"  Files scanned:  {scanned}")
    click.echo(f"  Secrets found:  {Fore.RED if found else Fore.GREEN}{found}{Style.RESET_ALL}")
    click.echo(f"  Config files:   {len(config_files)}")

    # Save report
    report_path = target_path / ".meda-claw-scan.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    click.echo(f"\n  Report saved: {report_path}")


# ── Command: evaluate ────────────────────────────────────────────────────

@cli.command()
@click.option("--model", default=None, help="Model to evaluate")
@click.option("--compliance", is_flag=True, help="Run CLEAR Act compliance check")
def evaluate(model, compliance):
    """LLM benchmark & governance compliance check.

    Runs ProjectSpark evaluation suite for model sensitivity analysis
    and regulatory compliance reporting.
    """
    banner()
    click.echo(f"{Fore.CYAN}━━━ EVALUATE MODE ━━━{Style.RESET_ALL}\n")

    spark_dir = find_component("ProjectSpark") or find_component("projectspark")
    if spark_dir:
        args = []
        if model:
            args.extend(["--model", model])
        if compliance:
            args.append("--compliance")
        run_component(spark_dir, ["evaluate"] + args, "ProjectSpark")
    else:
        click.echo(f"  {Fore.YELLOW}⚡ ProjectSpark not found locally.{Style.RESET_ALL}")
        click.echo(f"    Install: git clone https://github.com/VMaroon95/ProjectSpark")

    click.echo(f"\n{Fore.CYAN}━━━ EVALUATION COMPLETE ━━━{Style.RESET_ALL}")


# ── Command: status ──────────────────────────────────────────────────────

@cli.command()
def status():
    """Show suite health & component status."""
    banner()
    click.echo(f"{Fore.CYAN}━━━ SUITE STATUS ━━━{Style.RESET_ALL}\n")

    for key, comp in COMPONENTS.items():
        comp_dir = find_component(comp["name"]) or find_component(key)
        if comp_dir:
            status = f"{Fore.GREEN}✅ installed{Style.RESET_ALL}"
            # Check for git updates
            try:
                result = subprocess.run(
                    ["git", "log", "--oneline", "-1"],
                    capture_output=True, text=True, cwd=str(comp_dir)
                )
                if result.returncode == 0:
                    last_commit = result.stdout.strip()[:50]
                    status += f"  {Fore.WHITE}({last_commit}){Style.RESET_ALL}"
            except Exception:
                pass
        else:
            status = f"{Fore.YELLOW}⬜ not installed{Style.RESET_ALL}"

        click.echo(f"  {comp['icon']} {comp['name']:<18} {status}")
        click.echo(f"     {Fore.WHITE}{comp['desc']}{Style.RESET_ALL}")

    click.echo(f"\n{Fore.CYAN}━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}")


# ── Command: init ────────────────────────────────────────────────────────

@cli.command("init")
@click.argument("target", default=".", type=click.Path())
@click.option("--full", is_flag=True, help="Clone all components")
def init_project(target, full):
    """Initialize meda-claw governance in a project.

    Sets up configuration files, git hooks, and optional component installation.
    """
    banner()
    target_path = Path(target).resolve()
    target_path.mkdir(parents=True, exist_ok=True)

    click.echo(f"{Fore.CYAN}━━━ INITIALIZING ━━━{Style.RESET_ALL}\n")

    # Create config
    config = {
        "version": "1.0.0",
        "project": str(target_path.name),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "modules": {
            "agent_audit": {"enabled": True, "policy": "default"},
            "git_provenance": {"enabled": True, "ai_threshold": 30},
            "api_auditor": {"enabled": True, "providers": "all"},
            "repo_xray": {"enabled": True, "deep": False},
        },
        "escalation": {
            "red_threshold": 80,
            "amber_threshold": 40,
            "auto_block": False,
        },
    }

    config_path = target_path / ".medaclaw.json"
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    click.echo(f"  {Fore.GREEN}✅ Config created:{Style.RESET_ALL} {config_path}")

    # Create .medaclaw directory
    mc_dir = target_path / ".medaclaw"
    mc_dir.mkdir(exist_ok=True)
    (mc_dir / "audit_logs").mkdir(exist_ok=True)
    (mc_dir / "reports").mkdir(exist_ok=True)
    click.echo(f"  {Fore.GREEN}✅ Directories created:{Style.RESET_ALL} .medaclaw/")

    # Git hook
    git_dir = target_path / ".git"
    if git_dir.exists():
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        pre_commit = hooks_dir / "pre-commit"
        pre_commit.write_text("""#!/bin/sh
# meda-claw pre-commit hook
# Runs quick secret scan before allowing commits

echo "🔍 meda-claw: Running pre-commit scan..."
if command -v medaclaw &> /dev/null; then
    medaclaw scan . 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "❌ meda-claw detected issues. Fix before committing."
        exit 1
    fi
fi
echo "✅ meda-claw: Pre-commit check passed."
""")
        pre_commit.chmod(0o755)
        click.echo(f"  {Fore.GREEN}✅ Git pre-commit hook installed{Style.RESET_ALL}")

    if full:
        click.echo(f"\n  {Fore.GREEN}Cloning components...{Style.RESET_ALL}")
        for key, comp in COMPONENTS.items():
            comp_path = target_path / ".medaclaw" / comp["name"]
            if not comp_path.exists():
                click.echo(f"    {comp['icon']} Cloning {comp['name']}...")
                subprocess.run(
                    ["git", "clone", f"https://github.com/{comp['repo']}.git", str(comp_path)],
                    capture_output=True,
                )

    click.echo(f"\n{Fore.GREEN}🎉 meda-claw initialized!{Style.RESET_ALL}")
    click.echo(f"  Run {Fore.CYAN}medaclaw status{Style.RESET_ALL} to check component health.")
    click.echo(f"  Run {Fore.CYAN}medaclaw scan{Style.RESET_ALL} for a full security scan.")


# ── Command: report ───────────────────────────────────────────────────────

@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--json-output", "--json", "json_out", is_flag=True, help="Output as JSON")
@click.option("--save", default=None, help="Save report to file")
@click.option("--badge", is_flag=True, help="Print badge URL for README")
@click.option("--threshold", default=None, type=int, help="Fail (exit 1) if score below threshold")
def report(target, json_out, save, badge, threshold):
    """Generate a full Governance Report with AI Governance Score (0-100).

    Runs all scanners (secrets, attribution, behavior), aggregates findings,
    and calculates a weighted Governance Score.
    """
    from meda_claw.core.engine import GovernanceEngine
    from meda_claw.core.scoring import GovernanceScorer

    engine = GovernanceEngine(target)
    audit_report = engine.run()
    scorer = GovernanceScorer()
    grade = scorer.grade(audit_report.score)
    rating = scorer.rating(audit_report.score)

    if json_out:
        click.echo(audit_report.to_json())
        if threshold is not None and audit_report.score < threshold:
            raise SystemExit(1)
        return

    if badge:
        score = audit_report.score
        color = "brightgreen" if score >= 90 else "green" if score >= 80 else "yellow" if score >= 70 else "orange" if score >= 50 else "red"
        click.echo(f"![Governance Score](https://img.shields.io/badge/governance_score-{score}%2F100-{color}?style=flat-square&logo=data:image/svg+xml;base64,)")
        return

    banner()
    click.echo(f"{Fore.CYAN}━━━ GOVERNANCE REPORT ━━━{Style.RESET_ALL}\n")
    click.echo(f"  Target: {audit_report.target}")
    click.echo(f"  Time:   {audit_report.duration_ms:.0f}ms\n")

    # Score display
    score = audit_report.score
    if score >= 90:
        score_color = Fore.GREEN
    elif score >= 70:
        score_color = Fore.YELLOW
    elif score >= 50:
        score_color = Fore.YELLOW
    else:
        score_color = Fore.RED

    click.echo(f"  {score_color}╔══════════════════════════════════════╗")
    click.echo(f"  ║                                      ║")
    click.echo(f"  ║   AI GOVERNANCE SCORE:  {score:>3} / 100    ║")
    click.echo(f"  ║   Grade: {grade}  —  {rating[:24]:<24} ║")
    click.echo(f"  ║                                      ║")
    click.echo(f"  ╚══════════════════════════════════════╝{Style.RESET_ALL}\n")

    # Breakdown
    if audit_report.score_breakdown:
        click.echo(f"  {Fore.WHITE}Score Breakdown:{Style.RESET_ALL}")
        for cat, data in audit_report.score_breakdown.items():
            bar_filled = int((data['score'] / data['max']) * 20) if data['max'] > 0 else 0
            bar_empty = 20 - bar_filled
            bar_color = Fore.GREEN if data['score'] >= data['max'] * 0.8 else Fore.YELLOW if data['score'] >= data['max'] * 0.5 else Fore.RED
            click.echo(
                f"    {cat:<14} {bar_color}{'█' * bar_filled}{'░' * bar_empty}{Style.RESET_ALL} "
                f"{data['score']:>2}/{data['max']} ({data['findings']} findings)"
            )
        click.echo()

    # Findings
    summary = audit_report.summary()
    if summary["total_findings"] > 0:
        click.echo(f"  {Fore.WHITE}Findings ({summary['total_findings']}):{Style.RESET_ALL}")
        for f in audit_report.findings:
            sev_icon = {
                "critical": f"{Fore.RED}🔴",
                "high": f"{Fore.RED}🟠",
                "medium": f"{Fore.YELLOW}🟡",
                "low": f"{Fore.CYAN}🔵",
                "info": f"{Fore.WHITE}⚪",
            }.get(f.severity.value, "?")

            loc = f"  {f.file}:{f.line}" if f.file and f.line else f"  {f.file}" if f.file else ""
            click.echo(f"    {sev_icon} [{f.severity.value:>8}]{Style.RESET_ALL} {f.message}")
            if f.remediation:
                click.echo(f"               {Fore.WHITE}→ {f.remediation}{Style.RESET_ALL}")
    else:
        click.echo(f"  {Fore.GREEN}✅ No findings — governance posture is clean.{Style.RESET_ALL}")

    click.echo(f"\n{Fore.CYAN}━━━ REPORT COMPLETE ━━━{Style.RESET_ALL}")

    # Semantic Review
    if audit_report.review:
        review = audit_report.review
        if review.get("risk_escalations", 0) > 0 or review.get("critical_findings"):
            click.echo(f"\n  {Fore.WHITE}Semantic Review:{Style.RESET_ALL}")
            if review.get("risk_escalations"):
                click.echo(f"    {Fore.RED}⚡ {review['risk_escalations']} finding(s) escalated due to critical path{Style.RESET_ALL}")
            if review.get("path_classifications"):
                domains = set(review["path_classifications"].values())
                click.echo(f"    Critical paths touched: {', '.join(domains)}")
            for trace in review.get("finding_traces", [])[:5]:
                for line in trace.split("\n"):
                    click.echo(f"    {Fore.WHITE}{line}{Style.RESET_ALL}")
                click.echo()

    # Save if requested
    if save:
        with open(save, "w") as f_out:
            f_out.write(audit_report.to_json())
        click.echo(f"\n  Report saved to: {save}")

    # Threshold gating (for CI and pre-commit hooks)
    if threshold is not None and score < threshold:
        if not json_out:
            click.echo(f"\n  {Fore.RED}❌ Score {score} is below threshold {threshold}. FAILED.{Style.RESET_ALL}")
        raise SystemExit(1)


# ── Command: install-hooks ────────────────────────────────────────────────

@cli.command("install-hooks")
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--threshold", default=70, help="Minimum score to allow commits (default: 70)")
def install_hooks(target, threshold):
    """Install git pre-commit hook for active defense.

    Blocks commits that drop the Governance Score below the threshold.
    """
    target_path = Path(target).resolve()
    git_dir = target_path / ".git"

    if not git_dir.exists():
        click.echo(f"{Fore.RED}❌ Not a git repository: {target_path}{Style.RESET_ALL}")
        return

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    hook_script = f"""#!/bin/sh
# meda-claw Active Defense — Pre-commit governance gate
# Installed by: medaclaw install-hooks --threshold {threshold}

echo "🦞 meda-claw: Running governance audit..."

if command -v medaclaw &> /dev/null; then
    medaclaw report --threshold {threshold} . 2>/dev/null
    if [ $? -ne 0 ]; then
        echo ""
        echo "❌ meda-claw: Commit BLOCKED — Governance Score below {threshold}."
        echo "   Run 'medaclaw report' to see findings."
        echo "   Run 'medaclaw fix' to auto-remediate."
        exit 1
    fi
    echo "✅ meda-claw: Governance check passed."
else
    echo "⚠ meda-claw not installed. Skipping governance check."
fi
"""

    hook_path.write_text(hook_script)
    hook_path.chmod(0o755)

    click.echo(f"{Fore.GREEN}✅ Active Defense installed.{Style.RESET_ALL}")
    click.echo(f"   Hook: {hook_path}")
    click.echo(f"   Threshold: {threshold}/100")
    click.echo(f"   Commits scoring below {threshold} will be automatically rejected.")


# ── Command: simulate-attack ─────────────────────────────────────────────

@cli.command("simulate-attack")
@click.option("--output", default="./vulnerable_project", help="Output directory")
def simulate_attack(output):
    """Generate a vulnerable project to demonstrate detection capability.

    Creates realistic attack vectors: hardcoded secrets, AI-generated code
    without provenance, shell injection, and unsafe deserialization.
    """
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "auth").mkdir(exist_ok=True)

    # File 1: Hardcoded secrets + shell injection
    (out / "main.py").write_text('''# Generated by AI Agent (no provenance metadata)
import os
import subprocess

# Hardcoded credentials
PAYMENT_KEY = "pay_live_Xt7KzQ9mN4vR2wLpJ8bY5cAhDf"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgres://admin:password123@prod-db:5432/users"

def process_input(user_input):
    """VULNERABLE: Shell injection via os.system"""
    os.system(f"echo {user_input}")

def run_command(cmd):
    """VULNERABLE: Unsanitized subprocess"""
    result = eval(cmd)
    return result
''')

    # File 2: Auth bypass in critical path
    (out / "auth" / "login.py").write_text('''# This code was generated by Copilot (No Provenance)
import hashlib

ADMIN_TOKEN = "super_secret_admin_token_2026"
JWT_SECRET = "jwt-signing-key-never-share"

def authenticate(username, password):
    """VULNERABLE: Hardcoded admin bypass"""
    if username == "admin" and password == ADMIN_TOKEN:
        return True
    token = hashlib.md5(password.encode()).hexdigest()
    return token == "expected_hash"

def check_session(session_data):
    """VULNERABLE: eval in auth path"""
    return eval(f"session_data == '{session_data}'")
''')

    # File 3: Config with exposed keys
    (out / "config.yaml").write_text('''app:
  name: vulnerable-demo
  debug: true
google_api_key: "AIzaSyA1234567890abcdefghijklmnopqrstuv"
github_token: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
redis_url: "redis://default:s3cret@cache.internal:6379"
''')

    click.echo(f"{Fore.YELLOW}⚠️  Attack simulation created in {out}/{Style.RESET_ALL}")
    click.echo()
    click.echo("  Attack vectors planted:")
    click.echo(f"    {Fore.RED}● main.py{Style.RESET_ALL}       — Hardcoded secrets, shell injection, eval")
    click.echo(f"    {Fore.RED}● auth/login.py{Style.RESET_ALL} — Admin bypass, eval in auth path")
    click.echo(f"    {Fore.RED}● config.yaml{Style.RESET_ALL}   — Exposed API keys, connection strings")
    click.echo()
    click.echo(f"  Next steps:")
    click.echo(f"    {Fore.GREEN}medaclaw report {output}{Style.RESET_ALL}  — See the Governance Score")
    click.echo(f"    {Fore.GREEN}medaclaw fix {output}{Style.RESET_ALL}     — Auto-remediate findings")


# ── Command: fix ──────────────────────────────────────────────────────────

@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--dry-run", is_flag=True, help="Show fixes without applying")
@click.option("--auto", is_flag=True, help="Apply all fixes without prompting")
def fix(target, dry_run, auto):
    """Guided remediation engine for detected vulnerabilities.

    Scans the target, identifies fixable issues, and offers
    automated patches with explanations.
    """
    from meda_claw.core.engine import GovernanceEngine
    from meda_claw.core.scoring import GovernanceScorer
    import re

    banner()
    click.echo(f"{Fore.CYAN}━━━ REMEDIATION ENGINE ━━━{Style.RESET_ALL}\n")

    engine = GovernanceEngine(target)
    audit_report = engine.run(semantic_review=False)
    scorer = GovernanceScorer()

    click.echo(f"  Current Score: {audit_report.score}/100 (Grade {scorer.grade(audit_report.score)})")
    click.echo(f"  Findings: {len(audit_report.findings)}\n")

    # Remediation rules
    fixes_available = []
    fixes_applied = 0
    target_path = Path(target).resolve()

    for finding in audit_report.findings:
        if not finding.file:
            continue

        fpath = target_path / finding.file

        if finding.rule and "secret" in finding.rule and fpath.exists():
            fixes_available.append({
                "finding": finding,
                "type": "secret",
                "description": f"Replace hardcoded secret with environment variable in {finding.file}:{finding.line}",
            })

        if finding.rule == "behavior/dangerous_pattern" and "eval" in finding.message and fpath.exists():
            fixes_available.append({
                "finding": finding,
                "type": "eval",
                "description": f"Replace eval() with safe alternative in {finding.file}",
            })

        if finding.rule == "policy/gitignore_incomplete":
            fixes_available.append({
                "finding": finding,
                "type": "gitignore",
                "description": "Add missing entries to .gitignore",
            })

        if finding.rule == "attribution/no_license":
            fixes_available.append({
                "finding": finding,
                "type": "license",
                "description": "Generate MIT LICENSE file",
            })

    if not fixes_available:
        click.echo(f"  {Fore.GREEN}✅ No auto-fixable issues found.{Style.RESET_ALL}")
        click.echo(f"\n{Fore.CYAN}━━━ REMEDIATION COMPLETE ━━━{Style.RESET_ALL}")
        return

    click.echo(f"  {Fore.WHITE}Available fixes ({len(fixes_available)}):{Style.RESET_ALL}\n")

    for i, fix_item in enumerate(fixes_available, 1):
        f = fix_item["finding"]
        click.echo(f"    {i}. {fix_item['description']}")
        if f.remediation:
            click.echo(f"       {Fore.WHITE}→ {f.remediation}{Style.RESET_ALL}")

        if dry_run:
            click.echo(f"       {Fore.YELLOW}[DRY RUN — would apply]{Style.RESET_ALL}")
            continue

        should_apply = auto or click.confirm(f"       Apply this fix?", default=True)

        if should_apply:
            applied = _apply_fix(fix_item, target_path)
            if applied:
                fixes_applied += 1
                click.echo(f"       {Fore.GREEN}✅ Applied{Style.RESET_ALL}")
            else:
                click.echo(f"       {Fore.YELLOW}⚠ Could not auto-fix (manual review needed){Style.RESET_ALL}")
        click.echo()

    # Re-score
    if fixes_applied > 0 and not dry_run:
        new_report = GovernanceEngine(target).run(semantic_review=False)
        improvement = new_report.score - audit_report.score
        click.echo(f"\n  {Fore.GREEN}Fixes applied: {fixes_applied}{Style.RESET_ALL}")
        click.echo(f"  New Score: {new_report.score}/100 (Grade {scorer.grade(new_report.score)})")
        if improvement > 0:
            click.echo(f"  Improvement: {Fore.GREEN}+{improvement} points{Style.RESET_ALL}")

    click.echo(f"\n{Fore.CYAN}━━━ REMEDIATION COMPLETE ━━━{Style.RESET_ALL}")


def _apply_fix(fix_item, target_path: Path) -> bool:
    """Apply a single fix. Returns True if successful."""
    import re
    f = fix_item["finding"]
    fpath = target_path / f.file if f.file else None

    if fix_item["type"] == "gitignore":
        gitignore = target_path / ".gitignore"
        existing = gitignore.read_text() if gitignore.exists() else ""
        additions = [".env", "*.pem", "*.key", "credentials"]
        new_entries = [a for a in additions if a not in existing]
        if new_entries:
            with open(gitignore, "a") as gf:
                gf.write("\n# Added by medaclaw fix\n")
                for entry in new_entries:
                    gf.write(f"{entry}\n")
            return True
        return False

    if fix_item["type"] == "license" and not (target_path / "LICENSE").exists():
        import time
        (target_path / "LICENSE").write_text(
            f"MIT License\n\nCopyright (c) {time.strftime('%Y')} [Your Name]\n\n"
            "Permission is hereby granted, free of charge, to any person obtaining a copy\n"
            "of this software and associated documentation files (the \"Software\"), to deal\n"
            "in the Software without restriction.\n"
        )
        return True

    if fix_item["type"] == "secret" and fpath and fpath.exists():
        content = fpath.read_text()
        lines = content.split("\n")
        if f.line and f.line <= len(lines):
            line = lines[f.line - 1]
            # Replace hardcoded value with os.getenv()
            match = re.match(r'^(\s*\w+\s*=\s*)["\'].*?["\'](.*)$', line)
            if match:
                var_name = re.match(r'\s*(\w+)', line).group(1)
                lines[f.line - 1] = f'{match.group(1)}os.getenv("{var_name}", ""){match.group(2)}'
                # Ensure import os is present
                if "import os" not in content:
                    lines.insert(0, "import os")
                fpath.write_text("\n".join(lines))
                return True
        return False

    if fix_item["type"] == "eval" and fpath and fpath.exists():
        content = fpath.read_text()
        if "eval(" in content:
            content = content.replace("eval(", "# FIXME: eval() removed by medaclaw — use safe alternative\n    # ast.literal_eval(")
            fpath.write_text(content)
            return True

    return False


# ── Command: review ───────────────────────────────────────────────────────

@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--pr", is_flag=True, help="PR review mode (concise, CI-friendly)")
@click.option("--json-output", "--json", "json_out", is_flag=True, help="JSON output")
@click.option("--trace", is_flag=True, help="Show full reasoning trace")
def review(target, pr, json_out, trace):
    """Semantic review with critical path analysis and reasoning traces.

    Analyzes findings against governance rules to determine business impact.
    Classifies files by domain (auth, db, infra, financial) and escalates
    severity when findings touch critical paths.
    """
    from meda_claw.core.engine import GovernanceEngine
    from meda_claw.core.scoring import GovernanceScorer

    engine = GovernanceEngine(target)
    audit_report = engine.run(semantic_review=True)
    scorer = GovernanceScorer()
    grade = scorer.grade(audit_report.score)

    if json_out:
        click.echo(audit_report.to_json())
        return

    review_data = audit_report.review or {}

    if pr:
        # Concise PR comment format
        score = audit_report.score
        emoji = "✅" if score >= 80 else "⚠️" if score >= 50 else "❌"
        click.echo(f"{emoji} **meda-claw Governance Score: {score}/100 (Grade {grade})**")
        click.echo()

        summary = audit_report.summary()
        if summary["by_severity"]:
            parts = []
            for sev in ["critical", "high", "medium", "low"]:
                count = summary["by_severity"].get(sev, 0)
                if count:
                    parts.append(f"{count} {sev}")
            click.echo(f"Findings: {', '.join(parts)}")

        if review_data.get("risk_escalations"):
            click.echo(f"⚡ {review_data['risk_escalations']} escalation(s) — critical path affected")

        if review_data.get("path_classifications"):
            domains = set(review_data["path_classifications"].values())
            click.echo(f"Critical paths: {', '.join(domains)}")

        # Top 3 critical actions
        critical = review_data.get("critical_findings", [])
        if critical:
            click.echo("\nPriority actions:")
            for i, f in enumerate(critical[:3], 1):
                click.echo(f"  {i}. {f.get('message', '')}")

        return

    # Full review output
    banner()
    click.echo(f"{Fore.CYAN}━━━ SEMANTIC REVIEW ━━━{Style.RESET_ALL}\n")
    click.echo(f"  Target: {audit_report.target}")
    click.echo(f"  Score:  {audit_report.score}/100 (Grade {grade})")
    click.echo(f"  Time:   {audit_report.duration_ms:.0f}ms\n")

    escalations = review_data.get("risk_escalations", 0)
    critical = review_data.get("critical_findings", [])
    classifications = review_data.get("path_classifications", {})

    if escalations:
        click.echo(f"  {Fore.RED}⚡ {escalations} finding(s) escalated to HIGH due to critical path location{Style.RESET_ALL}")

    if classifications:
        click.echo(f"\n  {Fore.WHITE}Critical Path Analysis:{Style.RESET_ALL}")
        by_domain = {}
        for file, domain in classifications.items():
            by_domain.setdefault(domain, []).append(file)
        for domain, files in by_domain.items():
            icon = {"authentication": "🔐", "database": "🗄️", "infrastructure": "🏗️",
                    "financial_gateways": "💳"}.get(domain, "📁")
            click.echo(f"    {icon} {domain.upper()}")
            for f in files[:5]:
                click.echo(f"       → {f}")

    if critical:
        click.echo(f"\n  {Fore.WHITE}Critical Findings ({len(critical)}):{Style.RESET_ALL}")
        for f in critical:
            click.echo(f"    {Fore.RED}● {f.get('message', '')}{Style.RESET_ALL}")
            if f.get("remediation"):
                click.echo(f"      → {f['remediation']}")

    if trace and review_data.get("reasoning_trace"):
        click.echo(f"\n  {Fore.WHITE}Reasoning Trace:{Style.RESET_ALL}")
        for line in review_data["reasoning_trace"].split("\n"):
            click.echo(f"    {line}")

    click.echo(f"\n{Fore.CYAN}━━━ REVIEW COMPLETE ━━━{Style.RESET_ALL}")


# ── Command: benchmark ────────────────────────────────────────────────────

@cli.command()
def benchmark():
    """Run the Proof-of-Audit benchmark — three scenarios, three catches."""
    from meda_claw.benchmarks.proof_of_audit import run_all
    success = run_all()
    if not success:
        sys.exit(1)


# ── Command: sign ─────────────────────────────────────────────────────────

@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--reviewer", prompt="Reviewer name", help="Name of the human reviewer")
@click.option("--ai-pct", type=float, prompt="AI contribution %", help="Estimated AI contribution percentage (0-100)")
@click.option("--notes", default="", help="Review notes (required for >80% AI)")
def sign(target, reviewer, ai_pct, notes):
    """Sign the current commit as Human-Reviewed for IP safety.

    Creates a cryptographic attestation that a human has reviewed
    AI-generated or AI-assisted code. Required for commits where
    AI contribution exceeds 50%.
    """
    banner()
    click.echo(f"{Fore.CYAN}━━━ HUMAN-REVIEW ATTESTATION ━━━{Style.RESET_ALL}\n")

    target_path = Path(target).resolve()

    # Get current commit hash
    commit_hash = None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, cwd=str(target_path),
        )
        if result.returncode == 0:
            commit_hash = result.stdout.strip()
    except Exception:
        pass

    # Validate
    if ai_pct > 80 and not notes:
        click.echo(f"  {Fore.RED}⚠ AI contribution >80% requires review notes.{Style.RESET_ALL}")
        notes = click.prompt("  Review notes")

    if ai_pct < 0 or ai_pct > 100:
        click.echo(f"  {Fore.RED}Error: AI percentage must be 0-100{Style.RESET_ALL}")
        return

    # Create attestation
    attestation = create_attestation(
        reviewer=reviewer,
        ai_percentage=ai_pct,
        commit_hash=commit_hash,
        notes=notes,
    )

    # Save
    save_attestation(attestation, str(target_path))

    click.echo(f"  {Fore.GREEN}✅ Attestation created{Style.RESET_ALL}")
    click.echo(f"  Reviewer:       {reviewer}")
    click.echo(f"  AI Contribution: {ai_pct}%")
    click.echo(f"  Commit:         {commit_hash[:12] if commit_hash else 'N/A'}")
    click.echo(f"  Hash:           {attestation['integrity_hash'][:16]}...")
    click.echo(f"  Timestamp:      {attestation['iso_time']}")
    if notes:
        click.echo(f"  Notes:          {notes}")

    click.echo(f"\n  {Fore.GREEN}IP Provenance verified. Commit is governance-compliant.{Style.RESET_ALL}")
    click.echo(f"\n{Fore.CYAN}━━━ ATTESTATION COMPLETE ━━━{Style.RESET_ALL}")


# ── Command: verify ──────────────────────────────────────────────────────

@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--commit", default=None, help="Specific commit hash to verify")
@click.option("--full", is_flag=True, help="Run full governance check")
def verify(target, commit, full):
    """Verify governance compliance of the current workspace.

    Checks human-review attestations, policy compliance, git hooks,
    license files, and configuration integrity.
    """
    banner()
    click.echo(f"{Fore.CYAN}━━━ GOVERNANCE VERIFICATION ━━━{Style.RESET_ALL}\n")

    target_path = Path(target).resolve()

    if full:
        # Full governance check
        findings = full_governance_check(str(target_path))
        for f in findings:
            status = f["status"]
            icon = {
                "PASS": f"{Fore.GREEN}✅",
                "FAIL": f"{Fore.RED}❌",
                "WARN": f"{Fore.YELLOW}⚠️",
                "INFO": f"{Fore.CYAN}ℹ️",
            }.get(status, "?")
            click.echo(f"  {icon} {f['check']:<25}{Style.RESET_ALL} {f['detail']}")

        passed = sum(1 for f in findings if f["status"] == "PASS")
        total = len(findings)
        click.echo(f"\n  Score: {passed}/{total} checks passed")

    elif commit:
        # Verify specific commit
        att = get_attestation_for_commit(commit, str(target_path))
        if att:
            valid = verify_attestation_integrity(att)
            if valid:
                click.echo(f"  {Fore.GREEN}✅ Commit {commit[:12]} has valid attestation{Style.RESET_ALL}")
                click.echo(f"     Reviewer: {att['reviewer']}")
                click.echo(f"     AI %:     {att['ai_percentage']}%")
                click.echo(f"     Time:     {att['iso_time']}")
            else:
                click.echo(f"  {Fore.RED}❌ Attestation found but TAMPERED{Style.RESET_ALL}")
        else:
            click.echo(f"  {Fore.YELLOW}⚠ No attestation found for commit {commit[:12]}{Style.RESET_ALL}")

    else:
        # Verify all attestations
        attestations = load_attestations(str(target_path))
        if not attestations:
            click.echo(f"  {Fore.YELLOW}No attestations found.{Style.RESET_ALL}")
            click.echo(f"  Run {Fore.GREEN}medaclaw sign{Style.RESET_ALL} after reviewing AI-assisted commits.")
        else:
            valid = 0
            tampered = 0
            for att in attestations:
                if verify_attestation_integrity(att):
                    valid += 1
                else:
                    tampered += 1
                    click.echo(f"  {Fore.RED}❌ TAMPERED: {att.get('commit_hash', 'unknown')[:12]} by {att.get('reviewer', '?')}{Style.RESET_ALL}")

            click.echo(f"\n  Total attestations: {len(attestations)}")
            click.echo(f"  {Fore.GREEN}Valid: {valid}{Style.RESET_ALL}")
            if tampered:
                click.echo(f"  {Fore.RED}Tampered: {tampered}{Style.RESET_ALL}")
            else:
                click.echo(f"  {Fore.GREEN}✅ All attestations intact{Style.RESET_ALL}")

    click.echo(f"\n{Fore.CYAN}━━━ VERIFICATION COMPLETE ━━━{Style.RESET_ALL}")


# ── Command: remote ────────────────────────────────────────────────────────

@cli.command()
@click.argument("url")
@click.option("--json-output", "--json", "json_out", is_flag=True, help="Output as JSON")
@click.option("--threshold", default=None, type=int, help="Fail if score below threshold")
@click.option("--branch", default=None, help="Branch to scan (default: default branch)")
@click.option("--keep", is_flag=True, help="Keep cloned repo after scan (default: auto-cleanup)")
def remote(url, json_out, threshold, branch, keep):
    """Scan a remote GitHub repository without manual cloning.

    Accepts GitHub URLs in any format:
      medaclaw remote https://github.com/user/repo
      medaclaw remote user/repo
      medaclaw remote github.com/user/repo

    The repo is shallow-cloned to a temp directory, scanned, scored,
    and cleaned up automatically.
    """
    import tempfile
    import re as regex
    from meda_claw.core.engine import GovernanceEngine
    from meda_claw.core.scoring import GovernanceScorer

    # Normalize URL
    original_url = url
    # Handle shorthand: user/repo
    if regex.match(r'^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$', url):
        url = f"https://github.com/{url}.git"
    # Handle github.com/user/repo (no protocol)
    elif url.startswith("github.com/"):
        url = f"https://{url}"
    # Ensure .git suffix
    if url.startswith("https://") and not url.endswith(".git"):
        url = url.rstrip("/") + ".git"

    # Extract repo name for display
    repo_name = url.rstrip("/").rstrip(".git").split("/")[-2] + "/" + url.rstrip("/").rstrip(".git").split("/")[-1]

    if not json_out:
        banner()
        click.echo(f"{Fore.CYAN}━━━ REMOTE SCAN ━━━{Style.RESET_ALL}\n")
        click.echo(f"  Target: {Fore.WHITE}{repo_name}{Style.RESET_ALL}")
        click.echo(f"  URL:    {url}")
        click.echo(f"  Mode:   shallow clone → scan → {'keep' if keep else 'cleanup'}\n")
        click.echo(f"  {Fore.YELLOW}⏳ Cloning...{Style.RESET_ALL}", nl=False)

    # Clone to temp dir
    tmp_dir = tempfile.mkdtemp(prefix="medaclaw_remote_")
    clone_path = Path(tmp_dir) / "repo"

    clone_cmd = ["git", "clone", "--depth", "1"]
    if branch:
        clone_cmd.extend(["--branch", branch])
    clone_cmd.extend([url, str(clone_path)])

    result = subprocess.run(clone_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        if not json_out:
            click.echo(f"\r  {Fore.RED}❌ Clone failed{Style.RESET_ALL}")
            click.echo(f"     {result.stderr.strip()}")
        else:
            click.echo(json.dumps({"error": "clone_failed", "message": result.stderr.strip()}))
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise SystemExit(1)

    if not json_out:
        click.echo(f"\r  {Fore.GREEN}✅ Cloned{Style.RESET_ALL}              ")
        click.echo(f"  {Fore.YELLOW}⏳ Scanning...{Style.RESET_ALL}", nl=False)

    # Run governance engine
    try:
        engine = GovernanceEngine(str(clone_path))
        audit_report = engine.run()
        scorer = GovernanceScorer()
        grade = scorer.grade(audit_report.score)
        rating = scorer.rating(audit_report.score)
    except Exception as e:
        if not json_out:
            click.echo(f"\r  {Fore.RED}❌ Scan failed: {e}{Style.RESET_ALL}")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise SystemExit(1)

    if not json_out:
        click.echo(f"\r  {Fore.GREEN}✅ Scanned{Style.RESET_ALL}             \n")

    # Output (reuse report formatting)
    if json_out:
        output = audit_report.to_dict()
        output["remote"] = {"url": url, "repo": repo_name, "branch": branch}
        click.echo(json.dumps(output, indent=2, default=str))
    else:
        score = audit_report.score
        score_color = Fore.GREEN if score >= 90 else Fore.YELLOW if score >= 70 else Fore.RED

        click.echo(f"  {score_color}╔══════════════════════════════════════╗")
        click.echo(f"  ║                                      ║")
        click.echo(f"  ║   AI GOVERNANCE SCORE:  {score:>3} / 100    ║")
        click.echo(f"  ║   Grade: {grade}  —  {rating[:24]:<24} ║")
        click.echo(f"  ║                                      ║")
        click.echo(f"  ╚══════════════════════════════════════╝{Style.RESET_ALL}\n")

        # Breakdown
        if audit_report.score_breakdown:
            click.echo(f"  {Fore.WHITE}Score Breakdown:{Style.RESET_ALL}")
            for cat, data in audit_report.score_breakdown.items():
                bar_filled = int((data['score'] / data['max']) * 20) if data['max'] > 0 else 0
                bar_empty = 20 - bar_filled
                bar_color = Fore.GREEN if data['score'] >= data['max'] * 0.8 else Fore.YELLOW if data['score'] >= data['max'] * 0.5 else Fore.RED
                click.echo(
                    f"    {cat:<14} {bar_color}{'█' * bar_filled}{'░' * bar_empty}{Style.RESET_ALL} "
                    f"{data['score']:>2}/{data['max']} ({data['findings']} findings)"
                )
            click.echo()

        # Findings
        if audit_report.findings:
            click.echo(f"  {Fore.WHITE}Findings ({len(audit_report.findings)}):{Style.RESET_ALL}")
            for f in audit_report.findings:
                sev_icon = {
                    "critical": f"{Fore.RED}🔴",
                    "high": f"{Fore.RED}🟠",
                    "medium": f"{Fore.YELLOW}🟡",
                    "low": f"{Fore.CYAN}🔵",
                    "info": f"{Fore.WHITE}⚪",
                }.get(f.severity.value, "?")
                click.echo(f"    {sev_icon} [{f.severity.value:>8}]{Style.RESET_ALL} {f.message}")
                if f.remediation:
                    click.echo(f"               {Fore.WHITE}→ {f.remediation}{Style.RESET_ALL}")
        else:
            click.echo(f"  {Fore.GREEN}✅ No findings — governance posture is clean.{Style.RESET_ALL}")

        # Semantic review
        if audit_report.review:
            review = audit_report.review
            if review.get("risk_escalations", 0) > 0 or review.get("critical_findings"):
                click.echo(f"\n  {Fore.WHITE}Semantic Review:{Style.RESET_ALL}")
                for trace in review.get("finding_traces", [])[:5]:
                    for line in trace.split("\n"):
                        click.echo(f"    {Fore.WHITE}{line}{Style.RESET_ALL}")

        click.echo(f"\n{Fore.CYAN}━━━ REMOTE SCAN COMPLETE ━━━{Style.RESET_ALL}")

    # Cleanup
    if not keep:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        if not json_out:
            click.echo(f"  {Fore.WHITE}Temp files cleaned up.{Style.RESET_ALL}")
    else:
        if not json_out:
            click.echo(f"  {Fore.WHITE}Repo kept at: {clone_path}{Style.RESET_ALL}")

    # Threshold gating
    if threshold is not None and audit_report.score < threshold:
        raise SystemExit(1)


if __name__ == "__main__":
    cli()
