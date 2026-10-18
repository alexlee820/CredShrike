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
        # every AI response, captured as plain dicts for the HTML report:
        # [{"kind":"goal"|"assistant"|"tool_results", ...}] in turn order
        self.transcript: list[dict] = []
        self._budget_final_requested = False
        self._executor = None
        self.stop_requested = False   # set by the UI/REPL to break the loop

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
        self.transcript.append({"kind": "goal", "text": goal})
        while True:
            if self.stop_requested:
                self.echo("[stopped] interrupted by user — returning partial state")
                return ("(stopped by user — no final report was produced; see the "
                        "live log and audit trail for what was collected)")
            response = self._create()
            self.messages.append({"role": "assistant", "content": response.content})

            # capture the AI response for the report transcript
            entry = {"kind": "assistant", "text": "", "tools": []}
            for block in response.content:
                btype = getattr(block, "type", "")
                if btype == "text":
                    entry["text"] += getattr(block, "text", "")
                elif btype == "tool_use":
                    entry["tools"].append({"name": block.name,
                                           "input": dict(block.input or {})})
            self.transcript.append(entry)

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
        transcript_items = []
        for block in response.content:
            if getattr(block, "type", "") != "tool_use":
                continue
            self.echo(f"  → {block.name}({_short(block.input)})")
            outcome = self.executor.execute(block.name, dict(block.input or {}))
            self.echo(f"  ← {block.name}: "
                      f"{'error' if outcome['is_error'] else 'ok'} ({len(outcome['content'])} chars)")
            transcript_items.append({"name": block.name,
                                     "ok": not outcome["is_error"],
                                     "chars": len(outcome["content"])})
            results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": outcome["content"],
                "is_error": outcome["is_error"],
            })
        if transcript_items:
            self.transcript.append({"kind": "tool_results", "items": transcript_items})
        return results

    def _create(self):
        kwargs = dict(
            model=self.policy.model,
            max_tokens=self.policy.max_tokens,
            system=self.system,
            tools=anthropic_tools(),
            messages=self.messages,
        )
        # adaptive thinking is an Anthropic-API feature; third-party
        # Anthropic-compatible endpoints (GLM/DeepSeek/...) may reject it
        if self.policy.thinking_mode != "off":
            kwargs["thinking"] = {"type": "adaptive"}
        return self.client.messages.create(**kwargs)


def _short(args: dict, limit: int = 100) -> str:
    inner = ", ".join(f"{k}={v!r}" for k, v in (args or {}).items())
    return inner if len(inner) <= limit else inner[: limit - 1] + "…"
