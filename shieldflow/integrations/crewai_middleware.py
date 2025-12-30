from typing import Any, Callable, Iterable, List, Union

from ..inspector import Inspector
from ..event_bus import DetectionEvent


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

    def _scan_text_for_injection(self, text: str, label: str) -> None:
        detections = self.inspector.detectors.detect_prompt(text)
        if detections:
            reason = "; ".join(d.reason for d in detections)
            self._emit_metadata_event(label, reason, detections, text)
            raise ValueError(f"ShieldFlow blocked {label}: {reason}")

    def _scan_metadata(self, payload: Any, label: str) -> None:
        """Recursively inspect tool/MCP/knowledge metadata for prompt injection."""

        if payload is None:
            return
        if isinstance(payload, str):
            self._scan_text_for_injection(payload, label)
            return
        if isinstance(payload, dict):
            for k, v in payload.items():
                self._scan_metadata(v, f"{label}.{k}")
            return
        if isinstance(payload, Iterable) and not isinstance(payload, (str, bytes)):
            for idx, item in enumerate(payload):
                self._scan_metadata(item, f"{label}[{idx}]")
            return

        desc = getattr(payload, "description", None)
        name = getattr(payload, "name", label)
        if desc:
            self._scan_text_for_injection(str(desc), f"{label}:{name}")
        else:
            self._scan_text_for_injection(str(payload), label)

    def validate_agent_metadata(self, agent: Any) -> None:
        """Guard tool/MCP/knowledge descriptions against prompt injection."""

        self._scan_metadata(getattr(agent, "tools", None), "tool")
        self._scan_metadata(getattr(agent, "mcp_tools", None), "mcp_tool")
        self._scan_metadata(getattr(agent, "mcp", None), "mcp")
        self._scan_metadata(getattr(agent, "knowledge", None), "knowledge")

    def _emit_metadata_event(self, label: str, reason: str, detections: Iterable[Any], text: str) -> None:
        sink = getattr(self.inspector, "event_sink", None)
        if not sink:
            return
        try:
            event = DetectionEvent(
                session_id=self.session_id,
                stage=f"metadata:{label}",
                action="block",
                reason=reason,
                trust_score=self.inspector.trust_engine.store.get(self.session_id),
                detections=[d.to_dict() for d in detections],
                redacted_text=None,
                original_text=text,
            )
            sink.send(event)
        except Exception:
            return

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

        self.validate_agent_metadata(agent)

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
