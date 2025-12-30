from typing import Any, Callable, Iterable, List, Union

from ..inspector import Inspector


class CrewAIMiddleware:
    """Lightweight middleware to wrap CrewAI agent runs.

    This class is framework-agnostic: it does not import CrewAI types directly,
    so it can be used without pulling CrewAI as a hard dependency.
    """

    def __init__(self, inspector: Inspector, session_id: str) -> None:
        self.inspector = inspector
        self.session_id = session_id

    def wrap_prompt(self, prompt: str) -> str:
        decision = self.inspector.inspect_prompt(self.session_id, prompt)
        if not decision.allowed:
            raise RuntimeError(f"ShieldFlow blocked prompt: {decision.reason}")
        return decision.redacted_text or prompt

    def wrap_response(self, response: str) -> str:
        decision = self.inspector.inspect_response(self.session_id, response)
        if not decision.allowed:
            raise RuntimeError(f"ShieldFlow blocked response: {decision.reason}")
        return response

    def wrap_tool(self, tool_name: str, call_tool: Callable[[], str]) -> str:
        # Use trust gate only (tool calls normally produce their own detections upstream).
        decision = self.inspector.trust_engine.apply(self.session_id, [])
        if not decision.allow_tools:
            raise RuntimeError(f"ShieldFlow denied tool {tool_name}: trust {decision.score}")
        return call_tool()

    def kickoff_guarded(self, agent: Any, messages: Union[str, List[dict]]) -> Any:
        """Guard a CrewAI agent kickoff by inspecting prompts and responses.

        Usage:
            guard = CrewAIMiddleware(inspector, session_id)
            result = guard.kickoff_guarded(agent, "Hello")

        - For string input: inspects/masks the prompt before kickoff.
        - For list-of-dict messages: inspects only user-role contents.
        - After kickoff, inspects the raw response (if present) for entropy/PII.
        """

        guarded_messages: Union[str, List[dict]]
        if isinstance(messages, str):
            guarded_messages = self.wrap_prompt(messages)
        else:
            guarded_messages = []
            for msg in messages:
                if msg.get("role") == "user" and "content" in msg:
                    new_content = self.wrap_prompt(str(msg["content"]))
                    guarded_messages.append({**msg, "content": new_content})
                else:
                    guarded_messages.append(msg)

        result = agent.kickoff(guarded_messages)  # type: ignore[arg-type]

        raw = getattr(result, "raw", None) or getattr(result, "response", None) or str(result)
        self.wrap_response(raw)
        return result
