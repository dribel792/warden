"""
Warden Policy Engine — core authorization logic.
Runs entirely locally. No network required for policy evaluation.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger("warden.engine")


# ─── Result Types ────────────────────────────────────────────────────────────

@dataclass
class Decision:
    allowed: bool
    action: str
    params: Dict[str, Any]
    reason: Optional[str] = None
    check_failed: Optional[str] = None   # which check blocked it
    escalate: bool = False
    latency_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __bool__(self):
        return self.allowed

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "escalate": self.escalate,
            "action": self.action,
            "params": self.params,
            "reason": self.reason,
            "check_failed": self.check_failed,
            "latency_ms": round(self.latency_ms, 3),
            "timestamp": self.timestamp,
        }


# ─── Budget Tracker ───────────────────────────────────────────────────────────

class BudgetTracker:
    """Tracks rolling spend windows in memory. Reset on process restart."""

    def __init__(self):
        # Each entry: list of (timestamp, amount)
        self._events: List[tuple] = []

    def record(self, amount: float):
        self._events.append((time.time(), amount))

    def spent_in_window(self, seconds: int) -> float:
        cutoff = time.time() - seconds
        return sum(amt for ts, amt in self._events if ts >= cutoff)

    def check(self, amount: float, limits: dict) -> Optional[str]:
        """
        limits: {per_transaction, hourly, daily, monthly}
        Returns a failure reason string, or None if within budget.
        """
        if "per_transaction" in limits:
            if amount > limits["per_transaction"]:
                return (
                    f"exceeds per_transaction limit "
                    f"({amount} > {limits['per_transaction']})"
                )

        windows = {
            "hourly": 3600,
            "daily": 86400,
            "monthly": 2592000,
        }
        for name, seconds in windows.items():
            if name in limits:
                spent = self.spent_in_window(seconds)
                if spent + amount > limits[name]:
                    return (
                        f"exceeds {name} budget "
                        f"(spent {spent:.2f} + {amount} > {limits[name]})"
                    )
        return None


# ─── Threat Pattern Checker ───────────────────────────────────────────────────

class ThreatChecker:
    """Checks actions against the seed threat pattern library."""

    def __init__(self, patterns_path: Optional[Path] = None):
        if patterns_path is None:
            patterns_path = Path(__file__).parent / "threats" / "patterns.yaml"
        self.patterns = self._load(patterns_path)

    def _load(self, path: Path) -> dict:
        if not path.exists():
            logger.warning(f"Threat patterns file not found: {path}")
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def check(self, action: str, params: Dict[str, Any]) -> Optional[str]:
        """Returns pattern name if a threat is detected, else None."""

        # Check prompt injection in any string field
        injection_patterns = self.patterns.get("prompt_injection", [])
        for key, value in params.items():
            if isinstance(value, str):
                for pattern in injection_patterns:
                    if pattern.lower() in value.lower():
                        return f"prompt_injection:{pattern[:30]}"

        # Check recipient against known malicious addresses
        malicious_addresses = set(self.patterns.get("malicious_addresses", []))
        recipient = params.get("recipient") or params.get("to") or params.get("address")
        if recipient and recipient.lower() in {a.lower() for a in malicious_addresses}:
            return f"known_malicious_address:{recipient}"

        # Check action-specific patterns
        action_patterns = self.patterns.get("action_patterns", {})
        for pattern_name, pattern_def in action_patterns.items():
            if action in pattern_def.get("actions", []):
                conditions = pattern_def.get("conditions", {})
                for field, bad_values in conditions.items():
                    val = params.get(field)
                    if val in bad_values:
                        return f"{pattern_name}:{field}={val}"

        return None


# ─── Policy Engine ────────────────────────────────────────────────────────────

class PolicyEngine:
    """
    Evaluates agent actions against a YAML policy file.
    All checks run locally — no network calls.
    """

    def __init__(self, policy: str | Path, agent_id: Optional[str] = None):
        self.policy_path = Path(policy)
        self._policy = self._load_policy()
        self.agent_id = agent_id or self._policy.get("agent_id", "unknown")
        self._budget = BudgetTracker()
        self._threat = ThreatChecker()

    def _load_policy(self) -> dict:
        if not self.policy_path.exists():
            raise FileNotFoundError(f"Policy file not found: {self.policy_path}")
        with open(self.policy_path) as f:
            return yaml.safe_load(f) or {}

    def reload(self):
        """Hot-reload policy from disk."""
        self._policy = self._load_policy()
        logger.info(f"Policy reloaded from {self.policy_path}")

    # ── Public API ────────────────────────────────────────────────────────────

    def check(self, action: str, params: Optional[Dict[str, Any]] = None) -> Decision:
        """
        Evaluate an action against the policy.
        Returns a Decision (allowed=True/False, reason, latency).
        """
        params = params or {}
        start = time.perf_counter()

        checks = [
            self._check_kill_switch,
            self._check_schedule,
            self._check_permission,
            self._check_constraints,
            self._check_budget,
            self._check_escalation,
            self._check_threats,
        ]

        for check_fn in checks:
            result = check_fn(action, params)
            if result is not None:
                allowed, reason, check_name, escalate = result
                elapsed = (time.perf_counter() - start) * 1000
                decision = Decision(
                    allowed=allowed,
                    escalate=escalate,
                    action=action,
                    params=params,
                    reason=reason,
                    check_failed=check_name if not allowed else None,
                    latency_ms=elapsed,
                )
                self._log(decision)
                return decision

        # All checks passed — record spend if applicable
        amount = self._extract_amount(params)
        if amount:
            self._budget.record(amount)

        elapsed = (time.perf_counter() - start) * 1000
        decision = Decision(
            allowed=True,
            action=action,
            params=params,
            reason="all_checks_passed",
            latency_ms=elapsed,
        )
        self._log(decision)
        return decision

    # ── Individual Checks ─────────────────────────────────────────────────────

    def _check_kill_switch(self, action, params):
        ks = self._policy.get("kill_switch", {})
        if ks.get("triggered", False):
            return (False, "kill_switch_active", "kill_switch", False)
        return None

    def _check_schedule(self, action, params):
        schedule = self._policy.get("schedule")
        if not schedule:
            return None

        import pytz
        from datetime import datetime

        tz_name = schedule.get("timezone", "UTC")
        try:
            tz = pytz.timezone(tz_name)
        except Exception:
            return None

        now = datetime.now(tz)
        day_name = now.strftime("%a").lower()  # mon, tue, ...
        current_time = now.strftime("%H:%M")

        windows = schedule.get("active_windows", [])
        for window in windows:
            days = [d.lower() for d in window.get("days", [])]
            if day_name in days:
                hours = window.get("hours", "00:00-23:59")
                start_str, end_str = hours.split("-")
                if start_str <= current_time <= end_str:
                    return None  # within an active window

        outside_action = schedule.get("outside_hours_action", "deny")
        if outside_action in ("deny", "deny_with_alert"):
            return (False, f"outside_operating_hours ({day_name} {current_time})", "schedule", False)
        return None

    def _check_permission(self, action, params):
        permissions = self._policy.get("permissions", [])
        if not permissions:
            return None  # no permissions block = allow all

        for perm in permissions:
            if perm.get("action") == action:
                return None  # action is permitted (constraints checked separately)

        # action not in any permission block
        return (False, f"action_not_permitted:{action}", "permission", False)

    def _check_constraints(self, action, params):
        permissions = self._policy.get("permissions", [])
        for perm in permissions:
            if perm.get("action") != action:
                continue
            constraints = perm.get("constraints", {})

            # Token allowlist
            token = params.get("token") or params.get("currency")
            allowed_tokens = constraints.get("tokens") or constraints.get("allowed_tokens")
            if token and allowed_tokens and token not in allowed_tokens:
                return (False, f"token_not_allowed:{token}", "constraint", False)

            # Per-tx amount (also in budgets, but constraints can have it too)
            amount = self._extract_amount(params)
            max_per_tx = constraints.get("max_amount_per_tx") or constraints.get("max_amount")
            if amount and max_per_tx and amount > max_per_tx:
                return (False, f"exceeds_constraint_per_tx ({amount} > {max_per_tx})", "constraint", False)

            # Approved recipients
            recipient = params.get("recipient") or params.get("to") or params.get("address")
            approved = constraints.get("approved_recipients")
            if recipient and approved is not None:
                if recipient not in approved:
                    return (False, f"recipient_not_approved:{recipient}", "constraint", False)

            # Blocked recipients
            blocked = constraints.get("blocked_recipients", [])
            if recipient and recipient in blocked:
                return (False, f"recipient_blocked:{recipient}", "constraint", False)

            # Approved DEXes
            dex = params.get("dex") or params.get("venue")
            approved_dexes = constraints.get("approved_dexes") or constraints.get("dexes")
            if dex and approved_dexes and dex not in approved_dexes:
                return (False, f"dex_not_approved:{dex}", "constraint", False)

            # Allowed domains (for api_call)
            url = params.get("url") or params.get("endpoint")
            if url:
                allowed_domains = constraints.get("allowed_domains")
                if allowed_domains:
                    matched = any(self._domain_match(url, d) for d in allowed_domains)
                    if not matched:
                        return (False, f"domain_not_allowed:{url}", "constraint", False)

                blocked_domains = constraints.get("blocked_domains", [])
                for bd in blocked_domains:
                    if self._domain_match(url, bd):
                        return (False, f"domain_blocked:{url}", "constraint", False)

        return None

    def _check_budget(self, action, params):
        budgets = self._policy.get("budgets")
        if not budgets:
            return None
        amount = self._extract_amount(params)
        if not amount:
            return None
        reason = self._budget.check(amount, budgets)
        if reason:
            return (False, reason, "budget", False)
        return None

    def _check_escalation(self, action, params):
        escalation = self._policy.get("escalation")
        if not escalation:
            return None

        triggers = escalation.get("triggers", [])
        amount = self._extract_amount(params)
        recipient = params.get("recipient") or params.get("to")

        for trigger in triggers:
            if "amount_above" in trigger and amount and amount > trigger["amount_above"]:
                return (False, f"escalation_required:amount_above_{trigger['amount_above']}", "escalation", True)

            if trigger.get("recipient_not_in_approved_list"):
                approved = []
                for perm in self._policy.get("permissions", []):
                    if perm.get("action") == action:
                        approved = perm.get("constraints", {}).get("approved_recipients", [])
                if recipient and approved and recipient not in approved:
                    return (False, "escalation_required:unknown_recipient", "escalation", True)

        return None

    def _check_threats(self, action, params):
        pattern = self._threat.check(action, params)
        if pattern:
            return (False, f"threat_detected:{pattern}", "threat", False)
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_amount(self, params: dict) -> Optional[float]:
        for key in ("amount", "amount_usd", "value", "size", "quantity"):
            val = params.get(key)
            if val is not None:
                try:
                    return float(val)
                except (TypeError, ValueError):
                    pass
        return None

    def _domain_match(self, url: str, pattern: str) -> bool:
        """Simple domain matching supporting * wildcards."""
        import fnmatch
        # Extract domain from URL
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc or url
        except Exception:
            domain = url
        return fnmatch.fnmatch(domain, pattern.lstrip("*.").replace("*.", "*."))

    def _log(self, decision: Decision):
        log = decision.to_dict()
        if decision.allowed:
            logger.info(json.dumps({"warden": log}))
        else:
            logger.warning(json.dumps({"warden": log}))


# ─── Convenience alias ────────────────────────────────────────────────────────

class AgentGuard(PolicyEngine):
    """Alias kept for backwards compatibility."""
    pass
