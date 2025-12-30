import json
from typing import Any, Dict, Iterable, Optional

from ..inspector import Inspector
from ..event_bus import DetectionEvent

try:
    from langchain.callbacks.base import BaseCallbackHandler
except ImportError:  # pragma: no cover - optional dependency
    class BaseCallbackHandler:  # type: ignore
        pass


class ShieldFlowCallbackHandler(BaseCallbackHandler):
    """LangChain callback that blocks or masks prompts before they reach the LLM."""

    def __init__(self, inspector: Inspector, session_id: str) -> None:
        super().__init__()
        self.inspector = inspector
        self.session_id = session_id

    def on_llm_start(self, serialized: Dict[str, Any], prompts: list, **kwargs: Any) -> Optional[Any]:
        if not prompts:
            return None
        checked = []
        for prompt in prompts:
            decision = self.inspector.inspect_prompt(self.session_id, prompt)
            if not decision.allowed:
                raise RuntimeError(f"ShieldFlow blocked prompt: {decision.reason}")
            checked.append(decision.redacted_text or prompt)
        # Mutate prompts in place so downstream LLM sees redacted version
        prompts[:] = checked
        return None

    def on_tool_start(self, serialized: Dict[str, Any], input_str: Any, **kwargs: Any) -> Optional[Any]:
        """Inspect tool call inputs for PII/injection before execution."""
        text = self._stringify(input_str)
        if not text:
            return None
        decision = self.inspector.inspect_prompt(self.session_id, text)
        if decision.detections or not decision.allowed:
            raise RuntimeError(f"ShieldFlow blocked tool input: {decision.reason}")
        return None

    def on_tool_end(self, output: Any, **kwargs: Any) -> Optional[Any]:
        """Inspect tool outputs to prevent prompt-injection via tool results."""

        text = self._stringify(output)
        if not text:
            return None
        decision = self.inspector.inspect_prompt(self.session_id, text)
        if decision.detections or not decision.allowed:
            raise RuntimeError(f"ShieldFlow blocked tool output: {decision.reason}")
        return None

    def on_llm_end(self, response: Any, **kwargs: Any) -> Optional[Any]:
        # Optionally inspect responses if available in the response object.
        content = None
        try:
            generations = response.generations  # type: ignore[attr-defined]
            if generations and generations[0] and hasattr(generations[0][0], "text"):
                content = generations[0][0].text
        except Exception:
            content = None
        if not content:
            return None
        decision = self.inspector.inspect_response(self.session_id, content)
        if decision.detections or not decision.allowed:
            raise RuntimeError(f"ShieldFlow blocked response: {decision.reason}")
        return None

    @staticmethod
    def _stringify(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value)
        except Exception:
            return str(value)


def validate_tool_metadata(tools: Iterable[Any], inspector: Inspector, session_id: str) -> None:
    """Scan tool descriptions for malicious prompt-injection text before registration.

    Raises ValueError if a description trips ShieldFlow detectors. This is intended to
    catch hostile MCP/LLM tool descriptors before they reach the agent runtime.
    """

    for tool in tools:
        desc = getattr(tool, "description", None)
        if not desc:
            continue
        detections = inspector.detectors.detect_prompt(str(desc))
        if detections:
            reason = "; ".join(d.reason for d in detections)
            _emit_metadata_event(inspector, session_id, tool, reason, detections, desc)
            raise ValueError(f"ShieldFlow blocked tool registration for '{getattr(tool, 'name', tool)}': {reason}")


def _emit_metadata_event(inspector: Inspector, session_id: str, tool: Any, reason: str, detections: Iterable[Any], desc: str) -> None:
    sink = getattr(inspector, "event_sink", None)
    if not sink:
        return
    try:
        event = DetectionEvent(
            session_id=session_id,
            stage="metadata:tool",
            action="block",
            reason=reason,
            trust_score=inspector.trust_engine.store.get(session_id),
            detections=[d.to_dict() for d in detections],
            redacted_text=None,
            original_text=str(desc),
        )
        sink.send(event)
    except Exception:
        return
