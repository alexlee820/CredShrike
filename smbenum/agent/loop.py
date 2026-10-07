"""The agent loop: user goal -> Claude -> tool_use -> executor -> tool_result
-> Claude -> … -> final report.

Manual loop (no framework): we own every turn, which is what makes the
safety model auditable — nothing reaches the network except through
ToolExecutor, and nothing enters the conversation except what we put there.

Anthropic API notes (per claude-api skill):
- model/thinking/max_tokens from Policy (adaptive thinking default)
- parallel tool_use blocks in one assistant message are executed and their
  tool_results returned together in ONE user message
- full assistant content blocks are appended back each turn (thinking blocks
  preserved) so the API sees a well-formed history
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from ..config import Policy
from .audit import AuditLog
from .prompts import build_system_prompt
from .session import AgentSession
from .tools import anthropic_tools

LOG = logging.getLogger(__name__)

MAX_TURNS_WITHOUT_PROGRESS = 4  # consecutive turns producing no usable output


class AgentLoop:
    def __init__(self, client, session: AgentSession, policy: Policy,
                 audit: AuditLog, echo: Optional[Callable[[str], None]] = None):
        self.client = client
        self.session = session
        self.policy = policy
        self.audit = audit
        self.echo = echo or (lambda line: None)
        self.system = build_system_prompt(session.credential, policy,
                                          session.allowed_hosts, session.dc)
        self.messages: list[dict] = []
        self._budget_final_requested = False
        self._executor = None

    @property
    def executor(self):
        if self._executor is None:
            from .executor import ToolExecutor
            self._executor = ToolExecutor(self.session, self.policy, self.audit)
        return self._executor

    # ------------------------------------------------------------------ #
    def run(self, goal: str) -> str:
        """Pursue one goal to completion; returns the final assistant text.
        Conversation state persists across calls (REPL follow-ups)."""
        self.messages.append({"role": "user", "content": goal})
        while True:
            response = self._create()
            self.messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "tool_use":
                tool_results = self._run_tool_uses(response)
                self.messages.append({"role": "user", "content": tool_results})
                if self.session.budget.exhausted and not self._budget_final_requested:
                    self._budget_final_requested = True
                    why = self.session.budget.why()
                    self.echo(f"[budget] {why} — requesting final summary")
                    self.messages.append({
                        "role": "user",
                        "content": f"Budget exhausted ({why}). Stop calling tools now and "
                                   f"write your final report from the evidence collected so far, "
                                   f"listing what remains uncovered under Limitations."})
                continue

            text = "".join(block.text for block in response.content
                           if getattr(block, "type", "") == "text")
            if not text and response.stop_reason not in ("end_turn", "stop_sequence"):
                # (rare) non-terminal empty turn — nudge once, then give up
                self.messages.append({"role": "user",
                                      "content": "Continue; if you are done, write the final report."})
                continue
            return text

    # ------------------------------------------------------------------ #
    def _run_tool_uses(self, response) -> list[dict]:
        """Execute every tool_use block; all results in ONE user message."""
        results = []
        for block in response.content:
            if getattr(block, "type", "") != "tool_use":
                continue
            self.echo(f"  → {block.name}({_short(block.input)})")
            outcome = self.executor.execute(block.name, dict(block.input or {}))
            self.echo(f"  ← {block.name}: "
                      f"{'error' if outcome['is_error'] else 'ok'} ({len(outcome['content'])} chars)")
            results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": outcome["content"],
                "is_error": outcome["is_error"],
            })
        return results

    def _create(self):
        return self.client.messages.create(
            model=self.policy.model,
            max_tokens=self.policy.max_tokens,
            thinking={"type": "adaptive"},
            system=self.system,
            tools=anthropic_tools(),
            messages=self.messages,
        )


def _short(args: dict, limit: int = 100) -> str:
    inner = ", ".join(f"{k}={v!r}" for k, v in (args or {}).items())
    return inner if len(inner) <= limit else inner[: limit - 1] + "…"
