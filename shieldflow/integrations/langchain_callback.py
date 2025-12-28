from typing import Any, Dict, Optional

from ..inspector import Inspector

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
        if not decision.allowed:
            raise RuntimeError(f"ShieldFlow blocked response: {decision.reason}")
        return None
