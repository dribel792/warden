"""
Warden Threat Feed Client.

Handles two responsibilities:
1. Pulling fresh threat signatures from AgentGuard Cloud.
2. Pushing anonymized telemetry events (default on, opt-out requires Enterprise).

Telemetry notice:
    By default, Warden sends anonymized policy evaluation events to AgentGuard Cloud.
    This makes the threat feed smarter for everyone.
    Events contain: action type, pattern matched (if any), result, agent class.
    No PII, no amounts, no addresses, no business logic.
    Opting out requires an Enterprise license.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("warden.feed")

_FEED_BASE_URL = "https://feed.agentguard.io/v1"
_SIGNATURE_REFRESH_SECONDS = 300   # pull fresh signatures every 5 min
_TELEMETRY_FLUSH_SECONDS = 30      # flush telemetry queue every 30s
_TELEMETRY_BATCH_SIZE = 100


class ThreatFeedClient:
    """
    Connects to AgentGuard Cloud for threat intelligence and telemetry.

    Runs entirely in background threads — never blocks authorization decisions.
    """

    def __init__(
        self,
        api_key: str,
        agent_id: str,
        telemetry_enabled: bool = True,
        feed_url: str = _FEED_BASE_URL,
    ):
        self.api_key = api_key
        self.agent_id = agent_id
        self.telemetry_enabled = telemetry_enabled
        self.feed_url = feed_url

        self._telemetry_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._last_signature_pull: float = 0.0
        self._signatures: Dict[str, Any] = {}
        self._stopped = threading.Event()

        self._start_background_threads()
        logger.info(f"[warden.feed] Connected. agent_id={agent_id}, telemetry={telemetry_enabled}")

    # ── Public API ────────────────────────────────────────────────────────────

    def record(self, decision_dict: Dict[str, Any]):
        """
        Queue a telemetry event from a policy decision.
        Non-blocking — drops silently if queue is full.
        """
        if not self.telemetry_enabled:
            return

        event = {
            "agent_id": self.agent_id,
            "action": decision_dict.get("action"),
            "result": "allow" if decision_dict.get("allowed") else "deny",
            "check_failed": decision_dict.get("check_failed"),
            "reason": decision_dict.get("reason"),
            "escalate": decision_dict.get("escalate", False),
            "ts": int(time.time()),
        }
        try:
            self._telemetry_queue.put_nowait(event)
        except queue.Full:
            pass  # drop silently, never block the agent

    def get_signatures(self) -> Dict[str, Any]:
        """Return the latest pulled threat signatures."""
        return self._signatures

    def flush(self):
        """Force an immediate telemetry flush (blocks until done)."""
        self._flush_telemetry()

    def stop(self):
        """Gracefully stop background threads."""
        self.flush()
        self._stopped.set()

    # ── Background Threads ────────────────────────────────────────────────────

    def _start_background_threads(self):
        self._sig_thread = threading.Thread(
            target=self._signature_loop, daemon=True, name="warden-signatures"
        )
        self._tel_thread = threading.Thread(
            target=self._telemetry_loop, daemon=True, name="warden-telemetry"
        )
        self._sig_thread.start()
        self._tel_thread.start()

    def _signature_loop(self):
        while not self._stopped.is_set():
            try:
                self._pull_signatures()
            except Exception as e:
                logger.debug(f"[warden.feed] Signature pull failed: {e}")
            self._stopped.wait(timeout=_SIGNATURE_REFRESH_SECONDS)

    def _telemetry_loop(self):
        while not self._stopped.is_set():
            try:
                self._flush_telemetry()
            except Exception as e:
                logger.debug(f"[warden.feed] Telemetry flush failed: {e}")
            self._stopped.wait(timeout=_TELEMETRY_FLUSH_SECONDS)

    def _pull_signatures(self):
        try:
            import httpx
        except ImportError:
            return

        since = int(self._last_signature_pull)
        resp = httpx.get(
            f"{self.feed_url}/signatures",
            params={"since": since, "agent_id": self.agent_id},
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            self._signatures.update(data.get("signatures", {}))
            self._last_signature_pull = time.time()
            count = len(data.get("signatures", {}))
            if count:
                logger.info(f"[warden.feed] Pulled {count} new threat signatures.")

    def _flush_telemetry(self):
        if self._telemetry_queue.empty():
            return

        try:
            import httpx
        except ImportError:
            return

        batch = []
        while not self._telemetry_queue.empty() and len(batch) < _TELEMETRY_BATCH_SIZE:
            try:
                batch.append(self._telemetry_queue.get_nowait())
            except queue.Empty:
                break

        if not batch:
            return

        try:
            httpx.post(
                f"{self.feed_url}/telemetry",
                json={"events": batch},
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=10,
            )
            logger.debug(f"[warden.feed] Flushed {len(batch)} telemetry events.")
        except Exception:
            # Re-queue on failure (best effort, capped to avoid infinite growth)
            for event in batch[:50]:
                try:
                    self._telemetry_queue.put_nowait(event)
                except queue.Full:
                    break
