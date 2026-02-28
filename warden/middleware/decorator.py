"""
Warden Python decorator — protect any function with a policy check.

Usage:
    from warden.middleware.decorator import guard

    @guard(policy="policy.yaml", action="token_transfer")
    def send_payment(recipient: str, amount: float, token: str = "USDC"):
        # Only runs if the policy allows it
        wallet.transfer(recipient, amount)
"""

from __future__ import annotations

import functools
import logging
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Union

from warden.engine import PolicyEngine

logger = logging.getLogger("warden.decorator")

# Module-level engine cache (keyed by policy path)
_engines: Dict[str, PolicyEngine] = {}


def _get_engine(policy: Union[str, Path]) -> PolicyEngine:
    key = str(Path(policy).resolve())
    if key not in _engines:
        _engines[key] = PolicyEngine(policy)
    return _engines[key]


def guard(
    policy: Union[str, Path],
    action: Optional[str] = None,
    params_from: Optional[Callable] = None,
    on_deny: Optional[Callable] = None,
    raise_on_deny: bool = True,
):
    """
    Decorator that wraps a function with a Warden policy check.

    Args:
        policy: Path to the YAML policy file.
        action: The action type to check against (e.g. "token_transfer").
                Defaults to the function name.
        params_from: Optional callable(args, kwargs) -> dict to extract
                     params for the policy check. Defaults to kwargs.
        on_deny: Optional callback(decision) called when an action is denied.
        raise_on_deny: If True (default), raises PermissionError on deny.
                       If False, returns None instead.

    Example:
        @guard(policy="policy.yaml", action="token_transfer")
        def transfer(recipient: str, amount: float, token: str):
            ...
    """
    def decorator(func: Callable) -> Callable:
        action_name = action or func.__name__

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            engine = _get_engine(policy)

            # Extract params for policy check
            if params_from is not None:
                check_params = params_from(args, kwargs)
            else:
                check_params = dict(kwargs)

            decision = engine.check(action_name, check_params)

            if decision.escalate:
                logger.warning(
                    f"[warden] ESCALATE: {action_name} requires human approval. "
                    f"Reason: {decision.reason}"
                )
                if raise_on_deny:
                    raise PermissionError(
                        f"Warden: action '{action_name}' requires escalation — {decision.reason}"
                    )
                return None

            if not decision.allowed:
                if on_deny:
                    on_deny(decision)
                logger.warning(
                    f"[warden] DENY: {action_name} blocked. Reason: {decision.reason}"
                )
                if raise_on_deny:
                    raise PermissionError(
                        f"Warden: action '{action_name}' denied — {decision.reason}"
                    )
                return None

            logger.debug(f"[warden] ALLOW: {action_name} ({decision.latency_ms:.2f}ms)")
            return func(*args, **kwargs)

        wrapper._warden_policy = str(policy)
        wrapper._warden_action = action_name
        return wrapper

    return decorator


class Warden:
    """
    Class-based guard. Use when you need more control than the decorator.

    Example:
        warden = Warden(policy="policy.yaml")

        def transfer(recipient, amount, token):
            result = warden.check("token_transfer", {
                "recipient": recipient,
                "amount": amount,
                "token": token
            })
            if not result.allowed:
                raise PermissionError(result.reason)
            execute_transfer(recipient, amount)
    """

    def __init__(self, policy: Union[str, Path]):
        self._engine = PolicyEngine(policy)

    def check(self, action: str, params: Optional[Dict[str, Any]] = None):
        return self._engine.check(action, params or {})

    def wrap(self, action: str, fn: Callable) -> Callable:
        """Wrap an existing function with a policy check for a given action."""
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            decision = self.check(action, dict(kwargs))
            if not decision.allowed:
                raise PermissionError(f"Warden: {decision.reason}")
            return fn(*args, **kwargs)
        return wrapped
