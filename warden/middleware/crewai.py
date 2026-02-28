"""
Warden CrewAI integration — guarded agent wrapper.

Usage:
    from warden.middleware.crewai import GuardedAgent

    agent = GuardedAgent(
        role="Financial Analyst",
        goal="Process invoices",
        backstory="...",
        policy="policy.yaml",
        tools=[transfer_tool, query_tool]
    )
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, List, Optional, Union

from warden.engine import PolicyEngine
from warden.middleware.langchain import GuardedToolkit

logger = logging.getLogger("warden.crewai")

try:
    from crewai import Agent
    _CREWAI_AVAILABLE = True
except ImportError:
    _CREWAI_AVAILABLE = False
    Agent = object


def _require_crewai():
    if not _CREWAI_AVAILABLE:
        raise ImportError(
            "CrewAI is not installed. Run: pip install 'warden[crewai]'"
        )


class GuardedAgent:
    """
    A CrewAI Agent with all tools wrapped by Warden policy enforcement.

    Identical interface to crewai.Agent — just add policy= parameter.

    Example:
        agent = GuardedAgent(
            role="Payment Processor",
            goal="Pay approved invoices",
            backstory="Handles vendor payments within budget.",
            policy="invoice_policy.yaml",
            tools=[pay_tool, query_tool],
            llm=my_llm
        )
    """

    def __init__(
        self,
        policy: Union[str, Path],
        tools: Optional[List[Any]] = None,
        action_map: Optional[dict] = None,
        **agent_kwargs,
    ):
        _require_crewai()

        self._engine = PolicyEngine(policy)
        raw_tools = tools or []

        # Wrap all tools with Warden
        toolkit = GuardedToolkit(policy)
        guarded_tools = toolkit.wrap(raw_tools, action_map=action_map)

        self._agent = Agent(tools=guarded_tools, **agent_kwargs)
        logger.info(
            f"[warden] GuardedAgent created: role={agent_kwargs.get('role')}, "
            f"tools={[t.name for t in raw_tools]}, policy={policy}"
        )

    def __getattr__(self, name: str) -> Any:
        """Proxy all attribute access to the inner CrewAI agent."""
        return getattr(self._agent, name)
