from typing import Callable, Dict, Optional

from .datadog import DatadogClient
from .inspector import InspectionDecision, Inspector


class GatewayProxy:
    """Synchronous reference proxy to wrap LLM calls with ShieldFlow decisions."""

    def __init__(self, inspector: Inspector, dd: Optional[DatadogClient] = None) -> None:
        self.inspector = inspector
        self.dd = dd or DatadogClient(enabled=False)

    def inspect_and_forward(
        self,
        session_id: str,
        prompt: str,
        call_model: Callable[[str], str],
        metadata: Optional[Dict[str, str]] = None,
    ) -> InspectionDecision:
        metadata = metadata or {}
        prompt_decision = self.inspector.inspect_prompt(session_id, prompt)
        self._emit_metrics("prompt", prompt_decision, metadata)
        if not prompt_decision.allowed:
            return prompt_decision
        outgoing = prompt_decision.redacted_text or prompt
        model_response = call_model(outgoing)
        response_decision = self.inspector.inspect_response(session_id, model_response)
        self._emit_metrics("response", response_decision, metadata)
        return response_decision

    def _emit_metrics(self, stage: str, decision: InspectionDecision, metadata: Dict[str, str]) -> None:
        tags = {"stage": stage, **metadata, "action": decision.action}
        self.dd.send_metric("shieldflow.trust_score", decision.trust.score, tags)
        self.dd.send_metric("shieldflow.blocks", 1 if decision.action == "block" else 0, tags)
        if decision.action == "block":
            text = f"Blocked at {stage}: {decision.reason}"
            self.dd.open_incident(title="ShieldFlow Block", text=text, tags=tags)  # type: ignore[arg-type]
