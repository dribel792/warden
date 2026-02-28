"""
Warden CLI — check, audit, validate policies from the terminal.

Usage:
    warden check --policy policy.yaml --action token_transfer --params '{"amount": 500, "token": "USDC"}'
    warden audit --log agent.log
    warden validate --policy policy.yaml
"""

import json
import sys
from pathlib import Path

import click
import yaml


@click.group()
def main():
    """Warden — authorization layer for AI agents."""
    pass


@main.command()
@click.option("--policy", "-p", required=True, help="Path to policy YAML file.")
@click.option("--action", "-a", required=True, help="Action type (e.g. token_transfer).")
@click.option("--params", default="{}", help="JSON params for the action.")
def check(policy, action, params):
    """Check a single action against a policy."""
    from warden.engine import PolicyEngine

    try:
        p = json.loads(params)
    except json.JSONDecodeError as e:
        click.echo(f"Error: invalid JSON params — {e}", err=True)
        sys.exit(1)

    try:
        engine = PolicyEngine(policy)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    decision = engine.check(action, p)

    if decision.allowed:
        click.echo(click.style(f"✓ ALLOW", fg="green", bold=True) + f"  {action}")
        click.echo(f"  Latency: {decision.latency_ms:.2f}ms")
    elif decision.escalate:
        click.echo(click.style(f"⚠ ESCALATE", fg="yellow", bold=True) + f"  {action}")
        click.echo(f"  Reason:  {decision.reason}")
        click.echo(f"  Latency: {decision.latency_ms:.2f}ms")
        sys.exit(2)
    else:
        click.echo(click.style(f"✗ DENY", fg="red", bold=True) + f"  {action}")
        click.echo(f"  Reason:  {decision.reason}")
        click.echo(f"  Check:   {decision.check_failed}")
        click.echo(f"  Latency: {decision.latency_ms:.2f}ms")
        sys.exit(1)


@main.command()
@click.option("--log", "-l", required=True, help="Path to structured JSON log file.")
def audit(log):
    """Summarize what got blocked and why from an agent log file."""
    log_path = Path(log)
    if not log_path.exists():
        click.echo(f"Error: log file not found: {log}", err=True)
        sys.exit(1)

    total = 0
    allowed = 0
    denied = 0
    escalated = 0
    reasons: dict = {}
    checks: dict = {}

    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                # Support both raw decision dicts and wrapped {"warden": {...}}
                if "warden" in entry:
                    entry = entry["warden"]
            except json.JSONDecodeError:
                continue

            if "allowed" not in entry:
                continue

            total += 1
            if entry.get("escalate"):
                escalated += 1
            elif entry.get("allowed"):
                allowed += 1
            else:
                denied += 1
                reason = entry.get("reason", "unknown")
                check = entry.get("check_failed", "unknown")
                reasons[reason] = reasons.get(reason, 0) + 1
                checks[check] = checks.get(check, 0) + 1

    click.echo(f"\n{'─'*40}")
    click.echo(f"  Warden Audit Report")
    click.echo(f"{'─'*40}")
    click.echo(f"  Total actions evaluated:  {total}")
    click.echo(click.style(f"  Allowed:                  {allowed}", fg="green"))
    click.echo(click.style(f"  Denied:                   {denied}", fg="red"))
    click.echo(click.style(f"  Escalated:                {escalated}", fg="yellow"))

    if reasons:
        click.echo(f"\n  Deny reasons:")
        for reason, count in sorted(reasons.items(), key=lambda x: -x[1]):
            click.echo(f"    {count:>4}x  {reason}")

    if checks:
        click.echo(f"\n  Failed checks:")
        for check, count in sorted(checks.items(), key=lambda x: -x[1]):
            click.echo(f"    {count:>4}x  {check}")

    click.echo(f"{'─'*40}\n")


@main.command()
@click.option("--policy", "-p", required=True, help="Path to policy YAML file.")
def validate(policy):
    """Validate a policy file for syntax and required fields."""
    path = Path(policy)
    if not path.exists():
        click.echo(f"Error: policy file not found: {policy}", err=True)
        sys.exit(1)

    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        click.echo(f"Error: invalid YAML — {e}", err=True)
        sys.exit(1)

    if not isinstance(data, dict):
        click.echo("Error: policy must be a YAML mapping.", err=True)
        sys.exit(1)

    warnings = []

    # Collect info
    agent_id = data.get("agent_id", "(not set)")
    permissions = data.get("permissions", [])
    budgets = data.get("budgets", {})
    escalation = data.get("escalation")
    schedule = data.get("schedule")
    kill_switch = data.get("kill_switch")

    if not data.get("agent_id"):
        warnings.append("agent_id not set — recommended for audit logs")
    if not permissions:
        warnings.append("No permissions defined — all actions will be allowed")
    if not budgets:
        warnings.append("No budgets defined — no spend limits enforced")

    click.echo(f"\n{'─'*40}")
    click.echo(f"  Warden Policy Validation")
    click.echo(f"{'─'*40}")
    click.echo(f"  File:        {path}")
    click.echo(f"  Agent ID:    {agent_id}")
    click.echo(f"  Permissions: {len(permissions)} action type(s)")
    click.echo(f"  Budgets:     {', '.join(budgets.keys()) if budgets else 'none'}")
    click.echo(f"  Escalation:  {'configured' if escalation else 'not set'}")
    click.echo(f"  Schedule:    {'configured' if schedule else 'not set'}")
    click.echo(f"  Kill switch: {'enabled' if kill_switch and kill_switch.get('enabled') else 'not set'}")

    if warnings:
        click.echo(f"\n  Warnings:")
        for w in warnings:
            click.echo(click.style(f"    ⚠  {w}", fg="yellow"))

    click.echo(click.style(f"\n  ✓ Policy is valid.\n", fg="green"))


if __name__ == "__main__":
    main()
