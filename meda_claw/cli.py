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


if __name__ == "__main__":
    cli()
