from typing import Callable

from ..inspector import Inspector


class CrewAIMiddleware:
    """Lightweight middleware to wrap CrewAI agent runs."""

    def __init__(self, inspector: Inspector, session_id: str) -> None:
        self.inspector = inspector
        self.session_id = session_id

    def wrap_prompt(self, prompt: str) -> str:
        decision = self.inspector.inspect_prompt(self.session_id, prompt)
        if not decision.allowed:
            raise RuntimeError(f"ShieldFlow blocked prompt: {decision.reason}")
        return decision.redacted_text or prompt

    def wrap_tool(self, tool_name: str, call_tool: Callable[[], str]) -> str:
        decision = self.inspector.trust_engine.apply(self.session_id, [])
        if not decision.allow_tools:
            raise RuntimeError(f"ShieldFlow denied tool {tool_name}: trust {decision.score}")
        return call_tool()

    def wrap_response(self, response: str) -> str:
        decision = self.inspector.inspect_response(self.session_id, response)
        if not decision.allowed:
            raise RuntimeError(f"ShieldFlow blocked response: {decision.reason}")
        return response
