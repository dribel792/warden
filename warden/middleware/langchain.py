"""
Warden LangChain integration — wraps LangChain tools with policy enforcement.

Usage:
    from warden.middleware.langchain import GuardedToolkit

    tools = [TransferTool(), SwapTool(), QueryTool()]
    toolkit = GuardedToolkit(policy="policy.yaml")
    safe_tools = toolkit.wrap(tools)

    agent = initialize_agent(tools=safe_tools, llm=llm, ...)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Union

from warden.engine import PolicyEngine

logger = logging.getLogger("warden.langchain")

try:
    from langchain.tools import BaseTool
    from langchain.callbacks.manager import CallbackManagerForToolRun
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False
    BaseTool = object
    CallbackManagerForToolRun = None


def _require_langchain():
    if not _LANGCHAIN_AVAILABLE:
        raise ImportError(
            "LangChain is not installed. Run: pip install 'warden[langchain]'"
        )


class GuardedTool(BaseTool if _LANGCHAIN_AVAILABLE else object):
    """
    Wraps a LangChain BaseTool with Warden policy enforcement.
    Every tool call is checked against the policy before execution.
    """

    def __init__(self, tool: Any, engine: PolicyEngine, action: Optional[str] = None):
        _require_langchain()
        self._inner_tool = tool
        self._engine = engine
        self._action = action or tool.name

        # Mirror the inner tool's metadata
        self.name = tool.name
        self.description = tool.description
        self.args_schema = getattr(tool, "args_schema", None)
        self.return_direct = getattr(tool, "return_direct", False)

    def _run(self, *args, run_manager: Optional[Any] = None, **kwargs) -> str:
        # Build params dict for policy check
        params = dict(kwargs)
        if args:
            params["_args"] = list(args)

        decision = self._engine.check(self._action, params)

        if decision.escalate:
            logger.warning(f"[warden] ESCALATE: tool={self.name}, reason={decision.reason}")
            return f"[WARDEN ESCALATE] Action '{self.name}' requires human approval: {decision.reason}"

        if not decision.allowed:
            logger.warning(f"[warden] DENY: tool={self.name}, reason={decision.reason}")
            return f"[WARDEN DENY] Action '{self.name}' was blocked: {decision.reason}"

        logger.debug(f"[warden] ALLOW: tool={self.name} ({decision.latency_ms:.2f}ms)")
        return self._inner_tool._run(*args, run_manager=run_manager, **kwargs)

    async def _arun(self, *args, run_manager: Optional[Any] = None, **kwargs) -> str:
        params = dict(kwargs)
        if args:
            params["_args"] = list(args)

        decision = self._engine.check(self._action, params)

        if decision.escalate:
            return f"[WARDEN ESCALATE] Action '{self.name}' requires human approval: {decision.reason}"

        if not decision.allowed:
            return f"[WARDEN DENY] Action '{self.name}' was blocked: {decision.reason}"

        if hasattr(self._inner_tool, "_arun"):
            return await self._inner_tool._arun(*args, run_manager=run_manager, **kwargs)
        return self._inner_tool._run(*args, **kwargs)


class GuardedToolkit:
    """
    Wraps a list of LangChain tools with Warden policy enforcement.

    Example:
        toolkit = GuardedToolkit(policy="policy.yaml")
        safe_tools = toolkit.wrap([transfer_tool, swap_tool, query_tool])
    """

    def __init__(self, policy: Union[str, Path]):
        _require_langchain()
        self._engine = PolicyEngine(policy)

    def wrap(self, tools: List[Any], action_map: Optional[Dict[str, str]] = None) -> List[GuardedTool]:
        """
        Wrap a list of LangChain tools.

        Args:
            tools: List of BaseTool instances.
            action_map: Optional dict mapping tool name → action type for the policy.
                        e.g. {"TransferFunds": "token_transfer", "SwapTokens": "swap"}
                        Defaults to tool.name.
        """
        action_map = action_map or {}
        return [
            GuardedTool(
                tool=tool,
                engine=self._engine,
                action=action_map.get(tool.name, tool.name)
            )
            for tool in tools
        ]
